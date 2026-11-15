/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // GET /api/visits - Public read access (anyone can view visits)
    if (request.method === "GET" && url.pathname === "/api/visits") {
      try {
        const username = url.searchParams.get("username");
        let query = "SELECT * FROM airport_visits";
        let params = [];

        if (username) {
          query += " WHERE username = ?";
          params.push(username);
        }

        query += " ORDER BY visit_date DESC";

        const { results } = await env.DB.prepare(query).bind(...params).all();
        return Response.json(results);
      } catch (err) {
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    // POST /api/visits - Protected write access (requires token)
    if (request.method === "POST" && url.pathname === "/api/visits") {
      // 1. Check for Authorization header
      const authHeader = request.headers.get("Authorization");
      const expectedToken = `Bearer ${env.API_SECRET}`;

      if (!authHeader || authHeader !== expectedToken) {
        return new Response(
          JSON.stringify({ error: "Unauthorized: Invalid or missing token" }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }

      // 2. Proceed with database insertion if authorized
      try {
        const body = await request.json();
        const { iata_code, airport_name, visit_date, notes, username } = body;

        if (!iata_code || !visit_date) {
          return new Response(
            JSON.stringify({ error: "Missing required fields: iata_code and visit_date" }),
            { status: 400, headers: { "Content-Type": "application/json" } }
          );
        }

        const info = await env.DB.prepare(
          "INSERT INTO airport_visits (iata_code, airport_name, visit_date, notes, username) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(
            iata_code,
            airport_name || null,
            visit_date,
            notes || null,
            username || null
          )
          .run();

        return Response.json({ success: true, changes: info.meta.changes });
      } catch (err) {
        return Response.json({ error: err.message }, { status: 500 });
      }
    }

    return new Response("Airport Tracker API is running. Use GET or POST /api/visits", {
      status: 200,
    });
  },
};