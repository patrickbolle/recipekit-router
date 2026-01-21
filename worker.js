// Cloudflare Worker for RecipeKit
// Routes traffic to Next.js app (fully migrated from legacy Nuxt)
//
// Routing:
// - Frontend pages → app.recipekit.com (Next.js)
// - Backend API → recipe-kit-next-server.onrender.com (Express)
// - OAuth paths → app.getrecipekit.com (Nuxt - auth redirects configured there)

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// Legacy cookie names - used for clearing old cookies
const shopToCookieName = (shop) => shop ? `routing_${shop.replace(/\./g, "_")}` : null;
const legacyBetaCookieName = (shop) => shop ? `beta_${shop.replace(/\./g, "_")}` : null;

const setCSPHeaders = (response, shop) => {
	if (!shop) return;
	// Validate shop domain format to prevent CSP injection
	if (!/^[a-zA-Z0-9][a-zA-Z0-9\-]*\.myshopify\.com$/.test(shop)) {
		console.error(`[Router] Invalid shop domain format: ${shop}`);
		return;
	}
	response.headers.set(
		"Content-Security-Policy",
		`frame-ancestors https://${shop} https://admin.shopify.com;`
	);
	response.headers.delete("X-Frame-Options");
	response.headers.delete("x-frame-options");
};

// ============================================================================
// MAIN HANDLER
// ============================================================================

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const cookies = request.headers.get("Cookie") || "";

		// Clone request body for POST/PUT/PATCH
		let requestBody = null;
		if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
			try {
				requestBody = await request.arrayBuffer();
			} catch (e) {
				console.error("[Router] Failed to read request body:", e);
			}
		}

		// Handle CORS preflight
		if (request.method === "OPTIONS") {
			return new Response(null, {
				status: 200,
				headers: {
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
					"Access-Control-Max-Age": "86400",
				}
			});
		}

		// ========================================================================
		// EXTRACT SHOP DOMAIN
		// ========================================================================
		const shop = url.searchParams.get("shop") || "";
		const shopFromCookie = cookies.match(/shopify-shop=([^;]+)/)?.[1] || null;
		const effectiveShop = shop || shopFromCookie;
		const isEmbedded = url.searchParams.get("embedded") === "1";

		// Diagnostic logging for shop resolution issues
		if (!effectiveShop && url.pathname !== "/" && !url.pathname.startsWith("/_next")) {
			console.warn(`[Router] ⚠️ NO SHOP RESOLVED for ${url.pathname}`, {
				shopFromQuery: shop || "(empty)",
				shopFromCookie: shopFromCookie || "(no cookie)",
				hasAuth: !!request.headers.get("authorization")
			});
		}

		// Check for legacy cookies to clear
		let legacyCookiesToClear = [];
		if (effectiveShop) {
			const routingCookie = shopToCookieName(effectiveShop);
			const betaCookie = legacyBetaCookieName(effectiveShop);
			if (cookies.includes(routingCookie) || cookies.includes(betaCookie)) {
				legacyCookiesToClear = [routingCookie, betaCookie];
				console.log(`[Router] Clearing legacy cookies for ${effectiveShop}`);
			}
		}

		try {
			// ====================================================================
			// DETERMINE TARGET URL
			// ====================================================================

			let targetUrl;
			const isNextAsset = url.pathname.startsWith("/_next/");
			const isStaticAsset = [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot"]
				.some(ext => url.pathname.toLowerCase().endsWith(ext));

			// OAuth paths still go to Nuxt (auth redirect URLs configured there)
			const oauthPaths = ["/auth", "/auth/callback", "/auth_redirect", "/create_charge"];
			const isOAuthPath = oauthPaths.some(p => url.pathname === p || url.pathname.startsWith(`${p}/`));

			// Backend API paths (go to Express server)
			const backendApiPaths = ["/recipes", "/generate", "/shop", "/blogs", "/articles",
			                         "/functions", "/resources", "/install", "/billing", "/rating",
			                         "/article-tags", "/api/apps"];
			const isBackendApi = backendApiPaths.some(p => url.pathname.startsWith(p));

			// Analytics API endpoints go to backend (but /analytics page goes to Next.js)
			const isAnalyticsApi = url.pathname.startsWith("/analytics/") &&
				!url.pathname.startsWith("/analytics/enable") && !url.pathname.startsWith("/analytics/scopes");

			if (isOAuthPath) {
				// OAuth still on Nuxt
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else if (isBackendApi || isAnalyticsApi) {
				// API requests go to Express backend
				const apiUrl = new URL(`https://recipe-kit-next-server.onrender.com${url.pathname}${url.search}`);
				if (!apiUrl.searchParams.has('shop') && effectiveShop) {
					apiUrl.searchParams.set('shop', effectiveShop);
				}
				// Log when API request goes out without shop parameter
				if (!apiUrl.searchParams.has('shop')) {
					console.error(`[Router] ❌ API REQUEST WITHOUT SHOP: ${url.pathname}`, {
						effectiveShop: effectiveShop || "(none)",
						method: request.method,
						hasAuth: !!request.headers.get("authorization")
					});
				}
				targetUrl = apiUrl.toString();
			} else if (isStaticAsset && !isNextAsset) {
				// Static assets from Nuxt (legacy)
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else {
				// Everything else goes to Next.js
				targetUrl = `https://app.recipekit.com${url.pathname}${url.search}`;
			}

			console.log(`[Router] ${effectiveShop || 'unknown'} -> ${url.pathname}`);

			// ====================================================================
			// PROXY THE REQUEST
			// ====================================================================

			const proxyHeaders = new Headers(request.headers);
			proxyHeaders.set("Host", new URL(targetUrl).hostname);
			proxyHeaders.set("X-Forwarded-Host", "recipe-kit-router.recipekit.workers.dev");
			proxyHeaders.set("X-Forwarded-Proto", "https");
			proxyHeaders.set("X-Worker-Secret", env.WORKER_SECRET || "development-secret-change-me");

			const proxyRequest = new Request(targetUrl, {
				method: request.method,
				headers: proxyHeaders,
				body: requestBody,
				redirect: "manual"
			});

			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 10000);

			let response = await fetch(proxyRequest, { signal: controller.signal });
			clearTimeout(timeoutId);

			// ====================================================================
			// HANDLE SPECIAL RESPONSES
			// ====================================================================

			// Handle /auth OAuth redirect extraction for embedded context
			const isAuthWithHost = url.pathname === "/auth" && url.searchParams.has("host");
			if (url.pathname === '/auth' && response.status === 200 && (isEmbedded || isAuthWithHost)) {
				const text = await response.text();
				const oauthMatch = text.match(/const permissionUrl = '([^']+)'/) ||
				                   text.match(/https:\/\/[^\/]+\/admin\/oauth\/authorize\?[^'"\s]+/);
				if (oauthMatch) {
					const oauthUrl = oauthMatch[1] || oauthMatch[0];
					return new Response(null, { status: 302, headers: { 'Location': oauthUrl } });
				}
				response = new Response(text, response);
			}

			// Handle redirects
			if (response.status >= 300 && response.status < 400) {
				const modified = new Response(response.body, response);
				if (isEmbedded) setCSPHeaders(modified, effectiveShop);

				// Rewrite internal redirects to stay on worker domain
				const location = response.headers.get("Location");
				if (!isEmbedded && location) {
					try {
						const locUrl = new URL(location);
						if (locUrl.hostname === "app.recipekit.com" || locUrl.hostname === "app.getrecipekit.com") {
							modified.headers.set("Location", locUrl.pathname + locUrl.search + locUrl.hash);
						}
					} catch (e) { /* Invalid URL, leave as-is */ }
				}
				return modified;
			}

			// ====================================================================
			// BUILD FINAL RESPONSE
			// ====================================================================

			const finalResponse = new Response(response.body, response);

			if (isEmbedded) setCSPHeaders(finalResponse, effectiveShop);

			// Clear any legacy routing cookies
			for (const cookieName of legacyCookiesToClear) {
				finalResponse.headers.append("Set-Cookie",
					`${cookieName}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=None`);
			}

			return finalResponse;

		} catch (error) {
			console.error("[Router] Error:", error);
			// Return error response instead of fallback
			return new Response(JSON.stringify({ error: "Router error", message: error.message }), {
				status: 502,
				headers: { "Content-Type": "application/json" }
			});
		}
	}
};
