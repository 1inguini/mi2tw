import { D1Database } from "@cloudflare/workers-types";
import { Hono, HonoRequest } from "hono";
import { setCookie, getCookie } from "hono/cookie";
import { logger } from "hono/logger";
import * as oauth from "oauth4webapi";
import type { Note, User } from "misskey-js/built/esm/entities";

type WebhookPayload = {
  server: string;
  hookId: string;
  userId: User["id"];
  eventId: string;
  createdAt: number;
} & (
  | { type: "follow" | "followed" | "unfollow"; body: { user: User } }
  | { type: "note" | "reply" | "renote"; body: { note: Note } }
);

type Env = {
  db: D1Database;
  twitter_client_id: string;
  twitter_client_secret: string;
};

const twitter_auth_server: oauth.AuthorizationServer = {
  issuer: "https://twitter.com/",
  authorization_endpoint: "https://twitter.com/i/oauth2/authorize",
  token_endpoint: "https://api.twitter.com/2/oauth2/token",
};

type Context = Readonly<{
  req: HonoRequest;
  sql: Sql;
  twitter: oauth.Client;
}>;

function context(req: HonoRequest, env: Env): Context {
  return {
    req,
    sql: prepareSql(env.db),
    twitter: {
      client_id: env.twitter_client_id,
      client_secret: env.twitter_client_secret,
      token_endpoint_auth_method: "client_secret_basic",
    },
  };
}

// // 合ってるかはわからん https://ja.wikipedia.org/wiki/Xorshift
// const int64max = 2n ** 64n - 1n;
// function lfsr64bit(seed: bigint): bigint {
//   let bits: bigint = seed & int64max;
//   bits ^= bits << 13n;
//   bits ^= bits >> 7n;
//   bits ^= bits << 17n;
//   return bits & int64max;
// }

type RowId = number;

type S256 = {
  code_verifier: string;
  code_challenge: string;
};

type TwitterAccount = {
  id: string;
  username: string;
  name: string | null;
};

type Webhook = {
  webhook_id: RowId;
  secret: string;
};

type Token = {
  access_token: string | null;
  vaild_until: number | null;
  refresh_token: string;
};

type StatementSigniture<P, R> = {
  param: P;
  return: R;
};
type WriteSigniture<P> = StatementSigniture<P, RowId>;
type ReadSigniture<R> = StatementSigniture<RowId, R>;

type PreparedStatementsSigniture = Readonly<{
  insert_s256: StatementSigniture<S256, string>;
  insert_webhook: WriteSigniture<Webhook>;
  insert_token: WriteSigniture<Token & { webhook_id: RowId }>;
  delete_webhook: WriteSigniture<RowId>;
  get_webhook: ReadSigniture<Webhook>;
  get_token_of_webhook: ReadSigniture<Token>;
}>;

type Query<S extends keyof PreparedStatementsSigniture> = [
  S,
  PreparedStatementsSigniture[S]["param"]
];

type PreparedStatements = {
  [S in keyof PreparedStatementsSigniture]: (
    _: Query<S>
  ) => D1PreparedStatement;
};

type Sql = Readonly<{
  batch<T = unknown>(
    queries: Query<keyof PreparedStatementsSigniture>[]
  ): Promise<D1Result<T>[]>;
  first<S extends keyof PreparedStatementsSigniture>(
    query: Query<S>
  ): Promise<PreparedStatementsSigniture[(typeof query)[0]]["return"] | null>;
  all<S extends keyof PreparedStatementsSigniture>(
    query: Query<S>
  ): Promise<D1Result<
    PreparedStatementsSigniture[(typeof query)[0]]["return"]
  > | null>;
}>;

function prepareSql(db: D1Database): Sql {
  const stmts: {
    [S in keyof PreparedStatementsSigniture]: D1PreparedStatement;
  } = {
    insert_s256: db.prepare(
      `INSERT OR IGNORE INTO s256(code_verifier, code_challenge)
          VALUES(?1, ?2)
          ON CONFLICT(code_verifier) DO NOTHING
          RETURNING rowid`
    ),
    insert_webhook: db.prepare(
      `INSERT OR IGNORE INTO webhook(webhook_id, secret)
          VALUES(?1, ?2)
          RETURNING rowid`
    ),
    insert_token: db.prepare(
      `INSERT OR REPLACE INTO token(webhook_id, access_token, valid_until, refresh_token)
        VALUES(?1, ?2, ?3, ?4)`
    ),
    delete_webhook: db.prepare(
      `DELETE FROM webhook WHERE webhook_id = ?1
        RETURNING rowid`
    ),
    get_webhook: db.prepare(
      `SELECT * FROM webhook
        WHERE webhook_id = ?1
        LIMIT 1`
    ),
    get_token_of_webhook: db.prepare(
      `SELECT * FROM token NATURAL INNER JOIN webhook
        WHERE webhook_id = ?1`
    ),
  };
  const prepared: PreparedStatements = {
    insert_s256: ([s, c]) => stmts[s].bind(c.code_verifier, c.code_challenge),
    insert_webhook: ([s, w]) => stmts[s].bind(w.webhook_id, w.secret),
    insert_token: ([s, t]) =>
      stmts[s].bind(
        t.webhook_id,
        t.access_token,
        t.vaild_until,
        t.refresh_token
      ),
    delete_webhook: ([s, id]) => stmts[s].bind(id),
    get_webhook: ([s, id]) => stmts[s].bind(id),
    get_token_of_webhook: ([s, id]) => stmts[s].bind(id),
  };
  return {
    batch: (queries) =>
      db.batch(
        queries.map(
          <S extends keyof PreparedStatementsSigniture>(query: Query<S>) =>
            prepared[query[0]](query)
        )
      ),
    first: (query) => {
      const prep = prepared[query[0]](query);
      console.log(JSON.parse(JSON.stringify(prep)));
      return prep.first();
    },
    all: (query) => {
      const prep = prepared[query[0]](query);
      console.log(JSON.parse(JSON.stringify(prep)));
      return prep.all();
    },
  };
}

async function fetch_twitter_account_of_token(
  access_token: string
): Promise<TwitterAccount | undefined> {
  const res = await await oauth.protectedResourceRequest(
    access_token,
    "GET",
    new URL("https://api.twitter.com/2/users/me")
  );
  console.log("response", res);
  if (res.status !== 200) return undefined;
  const twitter = (await res.json<{ data: TwitterAccount }>()).data;
  return ((t): t is TwitterAccount => true)(twitter) ? twitter : undefined;
}

function random_hex(bytes: number) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(text: string) {
  const uint8 = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", uint8);
  return Array.from(new Uint8Array(digest))
    .map((v) => v.toString(16).padStart(2, "0"))
    .join("");
}

async function new_webhook(ctx: Context): Promise<Webhook> {
  const webhook: Webhook = {
    webhook_id: parseInt(random_hex(4), 16),
    secret: random_hex(16),
  };
  if (await ctx.sql.first(["insert_webhook", webhook])) {
    return webhook;
  } else {
    return new_webhook(ctx);
  }
}
function webhook_hex(w: Webhook) {
  return "0x" + w.webhook_id.toString(16).padStart(8, "0");
}

function no_search(url: string): URL {
  const u: URL = new URL(url);
  u.search = "";
  return u;
}

async function s256_memo(ctx: Context, code_verifier: string): Promise<void> {
  const code_challenge: string = ""; // BASE64_URL_ENCODE(SHA256(ASCII(code_verifier)))
  await ctx.sql.first(["insert_s256", { code_verifier, code_challenge }]);
}

function token_from_response({
  access_token,
  expires_in,
  refresh_token,
}: oauth.TokenEndpointResponse): Token | undefined {
  return refresh_token
    ? {
        access_token,
        vaild_until: expires_in ? Date.now() + expires_in * 60 : null,
        refresh_token,
      }
    : undefined;
}

async function twitter_auth(
  ctx: Context,
  redirect_uri: URL,
  state: string
): Promise<Token | oauth.OAuth2Error> {
  const url = new URL(ctx.req.url);
  const params = oauth.validateAuthResponse(
    twitter_auth_server,
    ctx.twitter,
    url,
    state
  );
  console.log(params);
  if (oauth.isOAuth2Error(params)) return params;
  const response = await oauth.authorizationCodeGrantRequest(
    twitter_auth_server,
    ctx.twitter,
    params,
    redirect_uri.href,
    "challenge"
  );
  console.log(response);
  const res = await oauth.processAuthorizationCodeOAuth2Response(
    twitter_auth_server,
    ctx.twitter,
    response
  );
  console.log(res);
  if (oauth.isOAuth2Error(res)) return res;
  console.log("Access Token Response", res);
  const token: Token | undefined = token_from_response(res);
  if (!token) return { error: "missing refresh_token" };
  console.log("token OK", token);
  return token;
}

async function twitter_refresh(
  ctx: Context,
  webhook_id: RowId,
  refresh_token: string
): Promise<Token | oauth.OAuth2Error> {
  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", ctx.twitter.client_id);
  params.append("refresh_token", refresh_token);
  const res: oauth.TokenEndpointResponse = await (
    await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(
          `${ctx.twitter.client_id}:${ctx.twitter.client_secret}`
        )}`,
      },
      body: params,
    })
  ).json<oauth.TokenEndpointResponse>();
  console.log("response", res);
  // if (oauth.isOAuth2Error(res)) return res;
  if (!res.refresh_token) return { error: "missing refresh_token" };
  const token: Token | undefined = token_from_response(res);
  if (!token) return { error: "missing access_token" };
  ctx.sql.first(["insert_token", { ...token, webhook_id }]);
  return token;
}

async function tweet(
  ctx: Context,
  access_token: string,
  server: string,
  note: Note
): Promise<Response> {
  const tweet = await oauth.protectedResourceRequest(
    access_token,
    "POST",
    new URL("https://api.twitter.com/2/tweets"),
    new Headers([["Content-type", "application/json"]]),
    await JSON.stringify({ text: `${note.text}\n\n${server}/notes/${note.id}` })
  );
  console.log("tweet", await tweet.json());
  return tweet;
}

export default new Hono<{ Bindings: Env }>({ strict: false })
  .use(logger())
  .get("/", async (c) => {
    return c.html(
      <html lang="ja-JP">
        <head>
          <meta charset="utf-8" />
        </head>
        <body>
          <h1>MisskeyのWebhook使って投稿をTwitterに転送するやつ</h1>
          <br />
          (ローカル限定でない、リプライでない、リノートでない、CWもついてない投稿のみ)
          <br />
          <a href="/new">新しいWebhookを生成</a>
        </body>
      </html>
    );
  })
  .get("/new", async (c) => {
    const ctx = context(c.req, c.env);
    const webhook: Webhook = await new_webhook(ctx);
    const webhook_url: URL = no_search(c.req.url);
    webhook_url.pathname = "/" + webhook_hex(webhook);
    setCookie(c, "secret", webhook.secret);
    return c.html(
      <html lang="ja-JP">
        <head>
          <meta charset="utf-8" />
        </head>
        <body>
          <p>
            これをMisskey側WebhookのURLに入力:
            <input type="text" readonly value={webhook_url.href} />
          </p>
          <p>
            これをMisskey側WebhookのSecretに入力:
            <input id="secret" type="text" readonly value={webhook.secret} />
          </p>
          <p>
            <a href={webhook_url.href /* + "?secret=" + webhook.secret */}>
              Webhookの設定に移動
            </a>
          </p>
        </body>
      </html>
    );
  })
  .get("/callback", async (c) => {
    const ctx = context(c.req, c.env);
    const { state } = ctx.req.query();
    const hex = state;
    const webhook: Webhook | null = await ctx.sql.first([
      "get_webhook",
      parseInt(state, 16),
    ]);
    if (!webhook)
      return c.html(
        <html>
          <head>
            <meta charset="utf-8" />
          </head>
          <body>
            <p>webhookの認証に失敗しました</p>
          </body>
        </html>
      );
    const token: Token | oauth.OAuth2Error = await twitter_auth(
      ctx,
      no_search(c.req.url),
      state
    );
    if ("error" in token) {
      console.log("twitter auth failed", token);
      return c.html(
        <html>
          <head>
            <meta charset="utf-8" />
          </head>
          <body>
            <p>twitterの認証に失敗しました</p>
          </body>
        </html>
      );
    }
    await ctx.sql.first([
      "insert_token",
      { webhook_id: webhook.webhook_id, ...token },
    ]);
    // const webhook_url: string = `${new URL(c.req.url).origin}/${hex}`;
    // return c.html(
    //   <html>
    //     <head>
    //       <meta charset="utf-8" />
    //     </head>
    //     <body>
    //       <p>Twitterアカウント @{twitter.username} に投稿</p>
    //       <p>
    //         これをMisskey側WebhookのURLに入力:
    //         <input type="text" readonly value={webhook_url} />
    //       </p>
    //       <p>
    //         これをMisskey側WebhookのSecretに入力:
    //         <input id="uid" type="text" readonly value={webhook.secret} />
    //       </p>
    //     </body>
    //   </html>
    // );
    return c.redirect(`/${hex}`);
  })
  .get("/:hex", async (c) => {
    const ctx = context(c.req, c.env);
    const { hex } = c.req.param();
    const secret = getCookie(c, "secret");
    const webhook = await ctx.sql.first(["get_webhook", parseInt(hex, 16)]);
    if (!webhook || webhook.secret !== secret)
      return c.html(
        <html>
          <head>
            <meta charset="utf-8" />
          </head>
          <body>
            <p>認証に失敗しました</p>
          </body>
        </html>
      );
    const redirect_uri: URL = new URL(c.req.url);
    redirect_uri.pathname = "/callback";
    redirect_uri.search = "";
    const auth_url: URL = new URL("https://twitter.com/i/oauth2/authorize");
    auth_url.searchParams.set("client_id", ctx.twitter.client_id);
    auth_url.searchParams.set("redirect_uri", redirect_uri.href);
    auth_url.searchParams.set("response_type", "code");
    auth_url.searchParams.set(
      "scope",
      "offline.access users.read tweet.read tweet.write"
    );
    auth_url.searchParams.set("code_challenge", "challenge");
    auth_url.searchParams.set("code_challenge_method", "plain");
    // const state: string = oauth.generateRandomState(); // CSRF?のなんからしい
    auth_url.searchParams.set("state", hex);
    console.log("auth_url", auth_url);
    const webhook_url = no_search(c.req.url);
    return c.html(
      <html>
        <head>
          <meta charset="utf-8" />
        </head>
        <body>
          <p>
            <a href={auth_url.href}>ここでTwitterの認証</a>
          </p>
          <p>
            <a href={webhook_url.href + "/delete"}>ここでWebhookを削除</a>
          </p>
        </body>
      </html>
    );
  })
  .get("/:hex/delete", async (c) => {
    const ctx: Context = context(c.req, c.env);
    const { hex } = c.req.param();
    const secret = getCookie(c, "secret");
    const webhook = await ctx.sql.first(["get_webhook", parseInt(hex, 16)]);
    if (!webhook || webhook.secret !== secret)
      return c.html(
        <html>
          <head>
            <meta charset="utf-8" />
          </head>
          <body>
            <p>認証に失敗しました</p>
          </body>
        </html>
      );
    if (await ctx.sql.first(["delete_webhook", parseInt(hex, 16)]))
      return c.redirect(new URL(c.req.url).origin);
    else
      return c.html(
        <html>
          <head>
            <meta charset="utf-8" />
          </head>
          <body>
            <p>Webhookを削除できませんでした</p>
          </body>
        </html>
      );
  })
  .post("/:hex", async (c) => {
    const ctx = context(c.req, c.env);
    const { hex } = c.req.param();
    const secret = c.req.header("x-misskey-hook-secret");
    const webhook = await ctx.sql.first(["get_webhook", parseInt(hex, 16)]);
    if (!webhook || webhook.secret !== secret) {
      c.status(400);
      return c.text("Webhookが認証できませんでした");
    }
    const payload: WebhookPayload = await c.req.json<WebhookPayload>();
    console.log("payload", payload);
    const token: Token | null = await ctx.sql.first([
      "get_token_of_webhook",
      webhook.webhook_id,
    ]);
    if (!token) {
      c.status(400);
      return c.text("twitterが認証できませんでした");
    }
    console.log("token", token);
    const refresh_token: boolean = ((b): b is true => true)(
      !token?.vaild_until ||
        (token?.vaild_until && Date.now() < token.vaild_until - 1000)
    );
    const updated_token: Token | oauth.OAuth2Error = refresh_token
      ? await twitter_refresh(ctx, webhook.webhook_id, token.refresh_token)
      : token;
    console.log("updated_token", updated_token);
    if (
      !((t): t is Token => true)(updated_token) ||
      !updated_token.access_token
    ) {
      c.status(400);
      return c.text("twitterが認証できませんでした");
    }
    const note = payload.type === "note" ? payload.body.note : null;
    if (
      note &&
      !note.renoteId &&
      !note.replyId &&
      !note.cw &&
      note.localOnly !== true &&
      note.text
    ) {
      const res: Response = await tweet(
        ctx,
        updated_token.access_token,
        payload.server,
        note
      );
      console.log("response", res.toString());
      return c.text("ツイートしました");
    }
    return c.text("ツイートする条件に合致しなかったので無視しました");
  });
