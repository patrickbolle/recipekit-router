// TEST VERSION - Cloudflare Worker for beta.getrecipekit.com
// Deploy this to beta.getrecipekit.com for testing beta redirect
//
// IMPORTANT PRINCIPLE: The Nuxt app is production and takes priority
// When in doubt about routing, default to the Nuxt app to ensure stability
// The Next.js app is still in beta/migration phase

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		
		// Clone the request body early if it's a POST/PUT/PATCH since we might need it multiple times
		let requestBody = null;
		if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
			try {
				requestBody = await request.text();
			} catch (e) {
				console.error("Failed to read request body:", e);
			}
		}
		
		// Handle CORS preflight requests
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

		// For testing, log all incoming requests
		const cookieHeader = request.headers.get("Cookie") || "";
		const shopFromUrl = url.searchParams.get("shop");
		const shopifyShopCookie = cookieHeader.match(/shopify-shop=([^;]+)/)?.[1];

		console.log("TEST WORKER - Request received:", {
			url: url.toString(),
			path: url.pathname,
			shopFromUrl,
			shopifyShopCookie,
			hasBetaFlag: url.searchParams.has("beta_enabled"),
			relevantBetaCookie: shopFromUrl
				? cookieHeader.includes(`beta_${shopFromUrl.replace(/\./g, "_")}=true`)
				: shopifyShopCookie
					? cookieHeader.includes(`beta_${shopifyShopCookie.replace(/\./g, "_")}=true`)
					: false
		});

		try {
			// SAFETY: Always default to old app if anything is uncertain
			let shouldUseBeta = false;

			// Get shop from URL
			const shop = url.searchParams.get("shop") || "";

			// Check 1: Look for beta flag in URL (from redirect)
			// Note: We'll handle this after we determine the effective shop
			const hasBetaFlag = url.searchParams.get("beta_enabled") === "true" || url.searchParams.get("from_beta_redirect") === "true";
			const hasBetaDisableFlag = url.searchParams.get("beta_enabled") === "false" || url.searchParams.has("beta_disabled");
			
			// Check if this is a return from Shopify pricing page (charge acceptance flow)
			const hasChargeId = url.searchParams.has("charge_id");
			const isChargePath = hasChargeId && (url.pathname === "/" || url.pathname === "");

			// Check 2: Look for beta cookies (shop-specific or for assets)
			const cookies = request.headers.get("Cookie") || "";

			// Function to verify beta status from database (with timeout for safety)
			const verifyBetaStatus = async (shopDomain) => {
				const controller = new AbortController();
				const timeoutId = setTimeout(() => controller.abort(), 2000); // 2 second timeout

				try {
					const prefsUrl = `https://app.getrecipekit.com/api/user-preferences?shop=${encodeURIComponent(shopDomain)}`;
					const prefsResponse = await fetch(prefsUrl, {
						headers: {
							"X-Forwarded-Host": "recipe-kit-router.recipekit.workers.dev",
							"X-Forwarded-Proto": "https"
						},
						signal: controller.signal
					});
					clearTimeout(timeoutId);

					if (prefsResponse.ok) {
						const data = await prefsResponse.json();
						return data.beta_app_enabled === true;
					}
				} catch (e) {
					clearTimeout(timeoutId);
					if (e.name === 'AbortError') {
						console.error("Beta status verification timed out - trusting cookie");
					} else {
						console.error("Failed to verify beta status:", e);
					}
				}
				return null; // Unknown - don't change behavior, trust the cookie
			};

			// Extract shop from cookie if not in URL (for assets)
			let shopFromCookie = null;
			const shopCookieMatch = cookies.match(/shopify-shop=([^;]+)/);
			if (shopCookieMatch) {
				shopFromCookie = shopCookieMatch[1];
			}

			// For routing decisions where we need a shop (like adding to API URLs), we can use the cookie
			const shopForRouting = shop || shopFromCookie;
			
			// Determine whether the cookie indicates beta for the cookie-derived shop
			const cookieShopBetaName = shopFromCookie ? `beta_${shopFromCookie.replace(/\./g, "_")}=true` : null;
			const hasShopBetaCookie = cookieShopBetaName ? cookies.includes(cookieShopBetaName) : false;
			
			// Determine effective shop for beta detection
			// - Prefer explicit shop from URL when present
			// - Allow beta redirects to rely on the cookie (hasBetaFlag)
			// - Allow established beta sessions to keep using the cookie-derived shop (hasShopBetaCookie)
			// - Static asset requests (_next/) never include shop, so fall back to cookie there too
			const isNextAsset = url.pathname.startsWith("/_next/");
			const effectiveShop =
				shop ||
				(hasBetaFlag ? shopFromCookie : null) ||
				(hasShopBetaCookie ? shopFromCookie : null) ||
				(isNextAsset ? shopFromCookie : null);
			
			// Check if beta should be enabled via flags or cookies
			// IMPORTANT: Only enable beta if explicitly requested via URL flag or valid cookie
			// But if beta is explicitly disabled, respect that
			if (hasBetaDisableFlag && effectiveShop) {
				shouldUseBeta = false;
				console.log("Beta explicitly DISABLED for shop:", effectiveShop);
			} else if (hasBetaFlag && effectiveShop) {
				shouldUseBeta = true;
				console.log("Beta flag detected in URL for shop:", effectiveShop);
			} else if (hasShopBetaCookie && effectiveShop === shopFromCookie && !hasBetaDisableFlag) {
				// Only trust cookie if the shop matches - prevent cross-shop beta activation
				shouldUseBeta = true;
				console.log("Beta cookie detected for matching shop:", effectiveShop);
			}
			
			// Note: charge_id can come from EITHER old or new app, so we don't make routing 
			// decisions based on it - we rely on the cookie as the source of truth
			
			// Check for shop-specific beta cookie - ONLY for the current shop
			// This is a secondary check - the shop must match exactly
			if (effectiveShop && !shouldUseBeta && !hasBetaDisableFlag) {
				const cookieName = `beta_${effectiveShop.replace(/\./g, "_")}=true`;
				if (cookies.includes(cookieName)) {
					// Additional validation: only enable if this is the right context
					// Don't enable beta just because a cookie exists - the shop must be correct
					console.log(`Found beta cookie for ${effectiveShop}, validating context...`);
					
					// Only enable beta if:
					// 1. We have a shop in the URL that matches, OR
					// 2. This is the shop from the cookie and we're in the right context
					if (shop === effectiveShop || (shopFromCookie === effectiveShop && !shop)) {
						shouldUseBeta = true;
						console.log("Beta enabled for validated shop:", effectiveShop);
					} else {
						console.log(`Beta cookie exists but context mismatch - shop: ${shop}, effectiveShop: ${effectiveShop}, shopFromCookie: ${shopFromCookie}`);
					}
				}
			}

			// If no shop is detected (shouldn't happen), default to old app
			if (!effectiveShop) {
				console.log("No shop detected in URL or cookies - defaulting to old app");
				shouldUseBeta = false;
			}

			// CRITICAL: For page loads (not assets), if we think beta is enabled via cookie,
			// verify against the database to handle cases where user disabled beta but cookie persists
			const isPageLoad = (url.pathname === "/" || url.pathname === "") && !isNextAsset && !url.pathname.startsWith("/_nuxt/");
			let shouldClearBetaCookie = false; // Track if we need to clear the stale cookie

			if (shouldUseBeta && hasShopBetaCookie && isPageLoad && effectiveShop && !hasBetaFlag) {
				console.log(`Beta cookie exists for ${effectiveShop}, verifying against database...`);
				const dbBetaEnabled = await verifyBetaStatus(effectiveShop);

				if (dbBetaEnabled === false) {
					console.log(`Database says beta is DISABLED for ${effectiveShop}. Overriding cookie and routing to old app.`);
					shouldUseBeta = false;
					shouldClearBetaCookie = true; // Mark for cookie clearing
				} else if (dbBetaEnabled === true) {
					console.log(`Database confirms beta is enabled for ${effectiveShop}.`);
				} else {
					console.log(`Could not verify beta status for ${effectiveShop}, trusting cookie.`);
				}
			}

			// Check if request is embedded
			const isEmbedded = url.searchParams.get("embedded") === "1";
			const hasIdToken = url.searchParams.has("id_token");
			const isInstallationFlow = hasIdToken && (url.pathname === "/" || url.pathname === "/auth");
			
			// Special case: /auth endpoint with host parameter is also considered embedded for OAuth flow
			const isAuthWithHost = url.pathname === "/auth" && url.searchParams.has("host");

			// Always defer embedded installation flows to the legacy Nuxt app, even for beta users
			// BUT only for actual installation flows (with id_token), not for regular embedded usage
			// EXCEPTION: If beta_enabled=true is in the URL, this is a beta enablement, not an installation
			if (isEmbedded && isInstallationFlow && !hasBetaFlag) {
				if (shouldUseBeta) {
					console.log(`Embedded installation flow detected for shop: ${effectiveShop}. Forcing legacy app for OAuth.`);
				}
				shouldUseBeta = false;
			}

			// Ignore old beta_user cookie - it's deprecated

			// SAFETY: Only proxy specific paths for beta users
			const allowedBetaPaths = [
				"/",
				"/api/",
				"/recipe", // Next.js recipe pages (singular - create, edit, generate)
				"/recipes", // Recipe listing and API
				"/settings",
				"/analytics",
				"/addons",
				"/onboarding",
				"/plan", // Billing/plan page
				"/install", // Installation pages
				"/_next/" // Next.js assets
				// Note: /_nuxt/ is handled specially and always goes to old app
			];

			const isAllowedPath = allowedBetaPaths.some((path) => url.pathname === path || url.pathname.startsWith(path));

			// Backend API paths that need special routing for beta users
			// Note: /recipe (singular) is for Next.js pages, /recipes (plural) is for API
			// IMPORTANT: /analytics/enable is OAuth callback - must go to Nuxt app, not backend
			const backendApiPaths = [
				"/recipes",
				"/generate", // Recipe generation endpoint
				// "/analytics", // Removed - analytics/enable OAuth callback needs Nuxt app
				"/shop",
				"/blogs",
				"/articles",
				"/functions",
				"/resources",
				"/install",
				"/billing",
				"/auth",
				"/api/apps" // Add this for the apps endpoint
			];
			
			// Special handling for analytics routes
			// /analytics/enable is OAuth callback - goes to Nuxt app  
			// Other /analytics/* routes can go to backend for data fetching
			// IMPORTANT: isBackendApi should only be true for beta users!
			// Non-beta users should have ALL requests go to the Nuxt app
			let isBackendApi = false;
			
			// Only set isBackendApi for BETA users
			if (shouldUseBeta) {
				isBackendApi = backendApiPaths.some((path) => url.pathname.startsWith(path));
				
				// Analytics routing: Data fetching endpoints can go to backend
				// OAuth-related endpoints (/analytics/enable, /analytics/scopes) stay in Nuxt (handled by legacyOnlyPaths)
				if (url.pathname.startsWith("/analytics") && 
					!url.pathname.startsWith("/analytics/enable") &&
					!url.pathname.startsWith("/analytics/scopes")) {
					// These analytics endpoints are for data fetching and can go to backend
					if (url.pathname.startsWith("/analytics/recipes") || 
						url.pathname.startsWith("/analytics/collect") ||
						url.pathname.startsWith("/analytics/attribution") ||
						url.pathname.startsWith("/analytics/summary") ||
						url.pathname.startsWith("/analytics/roi") ||
						url.pathname.startsWith("/analytics/latest-analysis") ||
						url.pathname.startsWith("/analytics/disable") ||
						url.pathname.match(/^\/analytics\/[^\/]+$/)) {
						isBackendApi = true;
					}
				}
			}

			// Determine target based on beta status and path type
			let targetUrl;

			// Check if this is a static asset (images, fonts, etc)
			const staticAssetExtensions = [".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot"];
			const isStaticAsset =
				staticAssetExtensions.some((ext) => url.pathname.toLowerCase().endsWith(ext)) ||
				url.pathname.startsWith("/cdn-") ||
				url.pathname.includes("/fonts/");

			// PRIORITY: The Nuxt app is production - it takes priority over Next.js beta
			// These endpoints MUST stay on the Nuxt app for reliability
			// When in doubt, route to Nuxt app to ensure existing customers aren't affected
			const legacyOnlyPaths = [
				"/create_charge",
				"/auth",
				"/auth/callback",
				"/auth_redirect",
				"/access_check_middleware",
				"/install",
				"/api/user-preferences", // Old app checks beta status
				"/analytics/enable", // OAuth callback handler only exists in Nuxt app
				"/analytics/scopes" // OAuth initiation should also stay in Nuxt for consistency
			];
			const isLegacyOnlyPath = legacyOnlyPaths.some((path) => url.pathname === path || url.pathname.startsWith(`${path}/`));

			// SPECIAL CASE: /_nuxt/ assets ALWAYS go to old app regardless of beta status
			if (url.pathname.startsWith("/_nuxt/")) {
				console.log(`Routing Nuxt asset to old app: ${url.pathname}`);
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			}
			// SPECIAL CASE: /_next/ assets for beta users go to Next.js app
			else if (url.pathname.startsWith("/_next/") && shouldUseBeta) {
				console.log(`Routing Next.js asset to beta app: ${url.pathname}`);
				targetUrl = `https://app.recipekit.com${url.pathname}${url.search}`;
			}
			// Static assets (images, fonts, CDN paths, etc) should go to old app where they're hosted
			else if (isLegacyOnlyPath) {
				console.log(`Routing legacy-only endpoint to old app: ${url.pathname}`);
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else if (isStaticAsset) {
				console.log(`Routing static asset to old app: ${url.pathname}`);
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else if (shouldUseBeta && isAllowedPath) {
				// Beta user - route to new infrastructure
				if (isBackendApi) {
					// API calls go to Express backend
					console.log(`BETA USER - Routing API to backend: ${url.pathname}`);
					// Add shop parameter if not already present (required for proxied auth)
					const targetUrlObj = new URL(`https://sapp.recipekit.com${url.pathname}${url.search}`);
					if (!targetUrlObj.searchParams.has('shop') && shopForRouting) {
						targetUrlObj.searchParams.set('shop', shopForRouting);
					}
					targetUrl = targetUrlObj.toString();
				} else {
					// Frontend routes go to Next.js app
					console.log(`BETA USER - Routing to Next.js frontend: ${url.pathname}`);
					targetUrl = `https://app.recipekit.com${url.pathname}${url.search}`;
				}
			} else if (shouldUseBeta && !isAllowedPath) {
				// Beta user accessing non-allowed path - still route to old app
				console.log(`BETA USER - Non-allowed path (${url.pathname}), routing to old app`);
				console.log(`Path not in allowed list. isAllowedPath=${isAllowedPath}`);
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			} else {
				console.log(`NORMAL USER - Routing to old app for path: ${url.pathname}, shop: ${effectiveShop}, beta: ${shouldUseBeta}`);
				// Route to OLD Nuxt app (it handles its own frontend + API)
				targetUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			}

			// Build the proxied request - create new headers to avoid conflicts
			const newHeaders = new Headers(request.headers);

			// Extract host from target URL
			const targetHost = new URL(targetUrl).hostname;

			// Set proper Host header for the target
			newHeaders.set("Host", targetHost);

			// Add forwarding headers - preserve the worker domain as the host
			// This is important for App Bridge to recognize the correct origin
			newHeaders.set("X-Forwarded-Host", "recipe-kit-router.recipekit.workers.dev");
			newHeaders.set("X-Forwarded-Proto", "https");
			newHeaders.set("X-Original-Path", url.pathname);
			newHeaders.set("X-Original-URL", url.toString());
			
			// Simple debug logging without interfering with headers
			if (isBackendApi) {
				console.log(`[Worker] API request to ${url.pathname} -> ${targetUrl}`);
				console.log(`[Worker] Has Authorization: ${newHeaders.has('Authorization')}, Beta: ${shouldUseBeta}`);
			}

			// Add secret for new app authentication (only beta app uses this)
			if (shouldUseBeta) {
				newHeaders.set("X-Worker-Secret", env.WORKER_SECRET || "development-secret-change-me");
			}

			// For embedded requests, we need to follow redirects to get the actual content
			// For non-embedded, we keep manual to preserve redirect behavior
			// Note: isEmbedded is already declared earlier in the code

			// Don't follow redirects - we need to handle OAuth flow specially
			const modifiedRequest = new Request(targetUrl, {
				method: request.method,
				headers: newHeaders,
				body: requestBody,
				redirect: "manual"
			});

			// Set timeout for request (fallback if slow)
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout for embedded

			try {
				const response = await fetch(modifiedRequest, {
					signal: controller.signal
				});

				clearTimeout(timeoutId);
				
				console.log(`Response from ${targetUrl}: status=${response.status}, embedded=${isEmbedded}, content-length=${response.headers.get('content-length')}`);
				
				// Special handling for /auth endpoint in embedded context
				// The /auth endpoint returns HTML with JavaScript that tries to redirect,
				// but Chrome blocks top-level navigation from iframes
				if (url.pathname === '/auth' && response.status === 200 && (isEmbedded || isAuthWithHost)) {
					console.log('[Worker] Detected /auth endpoint response in embedded context');
					
					// Parse the OAuth URL from the response body
					const responseText = await response.text();
					
					// Look for the permission URL in the JavaScript
					const permissionUrlMatch = responseText.match(/const permissionUrl = '([^']+)'/);
					let oauthUrl = null;
					
					if (permissionUrlMatch) {
						oauthUrl = permissionUrlMatch[1];
						console.log('[Worker] Extracted OAuth URL from permissionUrl variable:', oauthUrl);
					} else {
						// Fallback: try to match the URL pattern directly
						const oauthMatch = responseText.match(/https:\/\/[^\/]+\/admin\/oauth\/authorize\?[^'"\s]+/);
						if (oauthMatch) {
							oauthUrl = oauthMatch[0];
							console.log('[Worker] Extracted OAuth URL via pattern match:', oauthUrl);
						}
					}
					
					if (oauthUrl) {
						console.log('[Worker] Returning server-side 302 redirect to OAuth URL');
						
						// Return a proper HTTP redirect instead of HTML with JavaScript
						// This will work in embedded context where JavaScript redirects are blocked
						return new Response(null, {
							status: 302,
							headers: {
								'Location': oauthUrl,
								'Content-Type': 'text/plain'
							}
						});
					} else {
						console.error('[Worker] Could not extract OAuth URL from /auth response');
						console.error('[Worker] Response text sample:', responseText.substring(0, 500));
						// Fall through to normal response handling
						response = new Response(responseText, response);
					}
				}

				// Check if response is valid
				if (shouldUseBeta && !response.ok && response.status >= 500) {
					console.error(`Beta app error: ${response.status} - falling back to old app`);
					throw new Error("Beta app returned error");
				}

				// Special handling for /api/user-preferences response
				// If the database says beta is disabled but we have a beta cookie, clear it
				if (url.pathname === '/api/user-preferences' && response.ok) {
					try {
						const responseClone = response.clone();
						const prefsData = await responseClone.json();

						if (prefsData.beta_app_enabled === false && effectiveShop) {
							const cookieName = `beta_${effectiveShop.replace(/\./g, "_")}`;
							const hasBetaCookie = cookies.includes(`${cookieName}=true`);

							if (hasBetaCookie) {
								console.log(`Database says beta disabled for ${effectiveShop}, but cookie exists. Clearing cookie.`);
								// We need to modify the response to include the Set-Cookie header
								const modifiedPrefsResponse = new Response(JSON.stringify(prefsData), response);
								modifiedPrefsResponse.headers.set("Content-Type", "application/json");
								modifiedPrefsResponse.headers.append("Set-Cookie", `${cookieName}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=None`);

								if (isEmbedded) {
									modifiedPrefsResponse.headers.set(
										"Content-Security-Policy",
										`frame-ancestors https://${shopForRouting} https://admin.shopify.com;`
									);
									modifiedPrefsResponse.headers.delete("X-Frame-Options");
									modifiedPrefsResponse.headers.delete("x-frame-options");
								}

								return modifiedPrefsResponse;
							}
						}
					} catch (jsonError) {
						console.error("Failed to parse user-preferences response:", jsonError);
						// Continue with normal response handling
					}
				}
				
				// Handle redirects - just pass them through with proper CSP
				if (response.status >= 300 && response.status < 400) {
					const location = response.headers.get("Location");
					console.log(`Redirect detected: ${location}, embedded: ${isEmbedded}`);
					
					const redirectResponse = new Response(response.body, response);
					
					// For embedded apps, ensure CSP is set
					if (isEmbedded) {
						redirectResponse.headers.set(
							"Content-Security-Policy",
							`frame-ancestors https://${shop || effectiveShop} https://admin.shopify.com;`
						);
						redirectResponse.headers.delete("X-Frame-Options");
						redirectResponse.headers.delete("x-frame-options");
					}
					
					// For non-embedded, rewrite location to stay on worker domain  
					if (!isEmbedded && location) {
						// Rewrite location to stay on worker domain
						let newLocation = location;
						if (location.startsWith("https://app.recipekit.com")) {
							newLocation = location.replace("https://app.recipekit.com", "");
						} else if (location.startsWith("https://app.getrecipekit.com")) {
							newLocation = location.replace("https://app.getrecipekit.com", "");
						}
						
						if (newLocation !== location) {
							console.log(`Rewriting redirect from ${location} to ${newLocation}`);
							redirectResponse.headers.set("Location", newLocation);
						}
					}
					
					return redirectResponse;
				}

				// Clone and modify response
				const modifiedResponse = new Response(response.body, response);
				
				// For embedded apps, ensure proper CSP headers
				if (isEmbedded) {
					// Set CSP for embedding - don't delete existing, just override
					modifiedResponse.headers.set(
						"Content-Security-Policy",
						`frame-ancestors https://${shopForRouting} https://admin.shopify.com;`
					);
					modifiedResponse.headers.delete("X-Frame-Options");
					modifiedResponse.headers.delete("x-frame-options");
				}

				// Handle beta cookies based on flags
				if (effectiveShop) {
					const cookieName = `beta_${effectiveShop.replace(/\./g, "_")}`;

					// Clear beta cookie if beta is explicitly disabled OR if database says it's disabled
					if (hasBetaDisableFlag || shouldClearBetaCookie) {
						console.log(`Clearing beta cookie for shop: ${effectiveShop} (${hasBetaDisableFlag ? 'explicitly disabled' : 'database override'})`);
						// Set cookie with Max-Age=0 to delete it
						modifiedResponse.headers.append("Set-Cookie", `${cookieName}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; SameSite=None`);
					}
					// Set beta cookie ONLY if beta was explicitly enabled via URL flag
					else if (shouldUseBeta && hasBetaFlag) {
						if (!cookies.includes(`${cookieName}=true`)) {
							console.log(`Setting beta cookie for shop: ${effectiveShop} (explicitly enabled via URL flag)`);
							modifiedResponse.headers.append("Set-Cookie", `${cookieName}=true; Path=/; Secure; SameSite=None; Max-Age=2592000`);
						}
					}
				}

				return modifiedResponse;
			} catch (betaError) {
				// SAFETY: If beta request fails, fall back to old app
				if (shouldUseBeta) {
					console.error("Beta proxy failed, falling back to old app:", betaError.message);

					// Try to serve old app instead
					const fallbackUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
					const fallbackRequest = new Request(fallbackUrl, {
						method: request.method,
						headers: request.headers,
						body: requestBody
					});

					const fallbackResponse = await fetch(fallbackRequest);
					const modifiedFallback = new Response(fallbackResponse.body, fallbackResponse);

					if (isEmbedded) {
						modifiedFallback.headers.set(
							"Content-Security-Policy",
							`frame-ancestors https://${shop || effectiveShop} https://admin.shopify.com;`
						);
						modifiedFallback.headers.delete("X-Frame-Options");
						modifiedFallback.headers.delete("x-frame-options");
					}

					// Clear beta cookie to prevent repeated failures
					modifiedFallback.headers.append("Set-Cookie", "beta_user=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");

					return modifiedFallback;
				}

				throw betaError;
			}
		} catch (error) {
			// ULTIMATE SAFETY: If anything fails, serve the old app
			console.error("Worker error, serving old app:", error);

			const fallbackUrl = `https://app.getrecipekit.com${url.pathname}${url.search}`;
			
			const fallbackRequest = new Request(fallbackUrl, {
				method: request.method,
				headers: request.headers,
				body: requestBody
			});

			const fallbackResponse = await fetch(fallbackRequest);
			const modifiedFallback = new Response(fallbackResponse.body, fallbackResponse);

			if (isEmbedded) {
				modifiedFallback.headers.set(
					"Content-Security-Policy",
					`frame-ancestors https://${shop || effectiveShop} https://admin.shopify.com;`
				);
				modifiedFallback.headers.delete("X-Frame-Options");
				modifiedFallback.headers.delete("x-frame-options");
			}

			return modifiedFallback;
		}
	}
};
