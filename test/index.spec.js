import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src";

describe("airport tracker worker", () => {
	it("responds with my message (unit style)", async () => {
		const request = new Request("http://example.com");
		// Create an empty context to pass to `worker.fetch()`.
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		// Wait for all `Promise`s passed to `ctx.waitUntil()` to settle before running test assertions
		await waitOnExecutionContext(ctx);
		expect(await response.text()).toMatchInlineSnapshot(`"Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports"`);
	});

	it("responds with my message (integration style)", async () => {
		const response = await SELF.fetch("http://example.com");
		expect(await response.text()).toMatchInlineSnapshot(`"Airport Tracker API is running. Endpoints: POST /api/login, POST /api/2fa/totp/setup, POST /api/webauthn/*, GET/POST/PATCH/DELETE /api/visits, GET /api/stats, GET/POST /api/airports"`);
	});
});
