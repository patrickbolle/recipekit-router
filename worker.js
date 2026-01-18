// Cloudflare Worker for RecipeKit
// Routes traffic between Next.js (primary) and Nuxt (legacy) apps
//
// ROUTING LOGIC (in priority order):
// 1. URL flags (?use_nextjs=true or ?use_nuxt=true) - explicit override
// 2. Routing cookie (routing_SHOP=nextjs|nuxt) - cached preference
// 3. Database check (first visit only) - shop's preference
// 4. Default: Next.js
//
// LEGACY COMPATIBILITY:
// - Old beta_SHOP=true cookies are treated as routing_SHOP=nextjs
// - Old ?beta_enabled=true/false params still work

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

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

const createFallbackResponse = async (url, method, headers, body, shop, isEmbedded) => {
	const fallbackUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
	const response = await fetch(new Request(fallbackUrl, { method, headers, body }));
	const modified = new Response(response.body, response);
	if (isEmbedded) setCSPHeaders(modified, shop);
	return modified;
};

// ============================================================================
// MAIN HANDLER
// ============================================================================

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const cookies = request.headers.get("Cookie") || "";

		// Clone request for POST/PUT/PATCH (may need for retry on fallback)
		// Use arrayBuffer to preserve binary data (important for file uploads)
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
		// VARIABLES (declared here so they're accessible in catch block)
		// ========================================================================
		let shop = url.searchParams.get("shop") || "";
		let shopFromCookie = cookies.match(/shopify-shop=([^;]+)/)?.[1] || null;
		let effectiveShop = shop || shopFromCookie;
		let isEmbedded = url.searchParams.get("embedded") === "1";
		let useNextjs = true; // Default to Next.js
		let cookieToSet = null; // Track cookie changes

		try {
			// ====================================================================
			// STEP 1: DETERMINE ROUTING PREFERENCE
			// ====================================================================

			// Priority 1: URL flags (explicit override)
			const urlWantsNextjs = url.searchParams.get("beta_enabled") === "true" ||
			                       url.searchParams.get("use_nextjs") === "true";
			const urlWantsNuxt = url.searchParams.get("beta_enabled") === "false" ||
			                     url.searchParams.get("beta_disabled") !== null ||
			                     url.searchParams.get("use_nuxt") === "true";

			if (urlWantsNuxt) {
				useNextjs = false;
				if (effectiveShop) cookieToSet = { shop: effectiveShop, value: "nuxt" };
				console.log(`[Router] URL flag requests Nuxt for ${effectiveShop}`);
			} else if (urlWantsNextjs) {
				useNextjs = true;
				if (effectiveShop) cookieToSet = { shop: effectiveShop, value: "nextjs" };
				console.log(`[Router] URL flag requests Next.js for ${effectiveShop}`);
			} else if (effectiveShop) {
				// Priority 2: Check for routing cookie
				const cookieName = shopToCookieName(effectiveShop);
				const cookieMatch = cookies.match(new RegExp(`${cookieName}=(nextjs|nuxt)`));

				if (cookieMatch) {
					useNextjs = cookieMatch[1] === "nextjs";
					console.log(`[Router] Cookie says ${cookieMatch[1]} for ${effectiveShop}`);
				} else {
					// Check for legacy beta cookie (backwards compatibility)
					const legacyCookie = legacyBetaCookieName(effectiveShop);
					if (cookies.includes(`${legacyCookie}=true`)) {
						useNextjs = true;
						console.log(`[Router] Legacy beta cookie found for ${effectiveShop}`);
					} else {
						// Priority 3: First visit - default to Next.js
						// Note: We no longer check the database. The old beta_app_enabled field
						// was for opt-IN to beta. Now Next.js is the default, so everyone gets it
						// unless they explicitly opt out via ?use_nuxt=true
						console.log(`[Router] First visit for ${effectiveShop}, defaulting to Next.js`);
					}
				}
			}

			// ====================================================================
			// STEP 2: SPECIAL CASES
			// ====================================================================

			// Installation flows always use Nuxt (OAuth lives there)
			const hasIdToken = url.searchParams.has("id_token");
			const isInstallationFlow = hasIdToken && (url.pathname === "/" || url.pathname === "/auth");
			if (isEmbedded && isInstallationFlow && !urlWantsNextjs) {
				useNextjs = false;
				console.log(`[Router] Installation flow - forcing Nuxt`);
			}

			// Legacy-only paths (OAuth, billing, etc.)
			// Note: /api/user-preferences removed - Next.js handles it now
			const legacyOnlyPaths = [
				"/create_charge", "/auth", "/auth/callback", "/auth_redirect",
				"/access_check_middleware", "/install",
				"/analytics/enable", "/analytics/scopes"
			];
			const isLegacyOnly = legacyOnlyPaths.some(p => url.pathname === p || url.pathname.startsWith(`${p}/`));

			// ====================================================================
			// STEP 3: DETERMINE TARGET URL
			// ====================================================================

			let targetUrl;
			const isNextAsset = url.pathname.startsWith("/_next/");
			const isNuxtAsset = url.pathname.startsWith("/_nuxt/");
			const isStaticAsset = [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot"]
				.some(ext => url.pathname.toLowerCase().endsWith(ext));

			// Allowed paths for Next.js
			const allowedNextPaths = ["/", "/api/", "/recipe", "/recipes", "/settings", "/analytics",
			                          "/addons", "/onboarding", "/plan", "/install", "/_next/"];
			const isAllowedPath = allowedNextPaths.some(p => url.pathname === p || url.pathname.startsWith(p));

			// Backend API paths (go to Express server for Next.js users)
			const backendApiPaths = ["/recipes", "/generate", "/shop", "/blogs", "/articles",
			                         "/functions", "/resources", "/install", "/billing", "/auth", "/api/apps"];
			const isBackendApi = useNextjs && backendApiPaths.some(p => url.pathname.startsWith(p));

			// Analytics data endpoints (not OAuth) can go to backend
			const isAnalyticsData = useNextjs && url.pathname.startsWith("/analytics") &&
				!url.pathname.startsWith("/analytics/enable") && !url.pathname.startsWith("/analytics/scopes");

			if (isNuxtAsset) {
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else if (isNextAsset && useNextjs) {
				targetUrl = `https://app.recipekit.com${url.pathname}${url.search}`;
			} else if (isLegacyOnly || isStaticAsset) {
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else if (useNextjs && isAllowedPath) {
				if (isBackendApi || isAnalyticsData) {
					const apiUrl = new URL(`https://recipe-kit-next-server.onrender.com${url.pathname}${url.search}`);
					if (!apiUrl.searchParams.has('shop') && effectiveShop) {
						apiUrl.searchParams.set('shop', effectiveShop);
					}
					targetUrl = apiUrl.toString();
				} else {
					targetUrl = `https://app.recipekit.com${url.pathname}${url.search}`;
				}
			} else {
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			}

			console.log(`[Router] ${effectiveShop || 'unknown'} -> ${useNextjs ? 'Next.js' : 'Nuxt'} (${url.pathname})`);

			// ====================================================================
			// STEP 4: PROXY THE REQUEST
			// ====================================================================

			const proxyHeaders = new Headers(request.headers);
			proxyHeaders.set("Host", new URL(targetUrl).hostname);
			proxyHeaders.set("X-Forwarded-Host", "recipe-kit-router.recipekit.workers.dev");
			proxyHeaders.set("X-Forwarded-Proto", "https");

			if (useNextjs) {
				proxyHeaders.set("X-Worker-Secret", env.WORKER_SECRET || "development-secret-change-me");
			}

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
			// STEP 5: HANDLE SPECIAL RESPONSES
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

			// Fallback to Nuxt on Next.js errors
			if (useNextjs && !response.ok && response.status >= 500) {
				console.error(`[Router] Next.js error ${response.status}, falling back to Nuxt`);
				return await createFallbackResponse(url, request.method, request.headers, requestBody, effectiveShop, isEmbedded);
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
			// STEP 6: BUILD FINAL RESPONSE
			// ====================================================================

			const finalResponse = new Response(response.body, response);

			if (isEmbedded) setCSPHeaders(finalResponse, effectiveShop);

			// Set routing cookie if needed
			if (cookieToSet) {
				const cookieName = shopToCookieName(cookieToSet.shop);
				finalResponse.headers.append("Set-Cookie",
					`${cookieName}=${cookieToSet.value}; Path=/; Secure; SameSite=None; Max-Age=2592000`);

				// Clear legacy cookies
				const legacyCookie = legacyBetaCookieName(cookieToSet.shop);
				finalResponse.headers.append("Set-Cookie",
					`${legacyCookie}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=None`);
			}

			return finalResponse;

		} catch (error) {
			// Ultimate fallback: serve Nuxt on any error
			console.error("[Router] Error, falling back to Nuxt:", error);
			return await createFallbackResponse(url, request.method, request.headers, requestBody, effectiveShop, isEmbedded);
		}
	}
};
