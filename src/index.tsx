import { D1Database } from "@cloudflare/workers-types";
import { Hono, HonoRequest } from "hono";
import { setCookie, getCookie } from "hono/cookie";
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

type Webhook = {
  id: RowId;
  secret: string;
};

export type TwitterAccount = {
  id: number;
  username: string;
  name?: string;
};

type TwitterToken = {
  twitter_id: RowId;
  access_token?: string;
  vaild_until?: number;
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
  insert_twitter: WriteSigniture<TwitterAccount>;
  insert_webhook_to_twitter: WriteSigniture<{
    webhook_id: RowId;
    twitter_id: RowId;
  }>;
  insert_twitter_token: WriteSigniture<TwitterToken>;
  delete_webhook: WriteSigniture<RowId>;
  get_webhook: ReadSigniture<Webhook>;
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
}>;

function prepareSql(db: D1Database): Sql {
  const stmts = {
    insert_s256: db.prepare(
      `INSERT INTO s256(code_verifier, code_challenge)
          VALUES(?1, ?2)
          RETURNING rowid`
    ),
    insert_webhook: db.prepare(
      `INSERT INTO webhook(webhook_id, secret)
          VALUES(?1, ?2)
          RETURNING rowid`
    ),
    insert_twitter: db.prepare(
      `INSERT INTO twitter(twitter_id, twitter_username, twitter_name)
          VALUES(?1, ?2, ?3)
          RETURNING rowid`
    ),
    insert_webhook_to_twitter: db.prepare(
      `INSERT INTO webhook_to_twitter(webhook_id, twitter_id)
          VALUES(?1, ?2)
          RETURNING rowid`
    ),
    insert_twitter_token: db.prepare(
      `INSERT INTO twitter_token(twitter_id, access_token, valid_until, refresh_token)
          VALUES(?1, ?2, ?3, ?4)
          RETURNING rowid`
    ),
    delete_webhook: db.prepare(
      `DELETE FROM webhook WHERE webhook_id = ?1
        RETURNING rowid`
    ),
    get_webhook: db.prepare(
      `SELECT * FROM webhook
        WHERE webhook_id = ?1 LIMIT 1`
    ),
  };
  const prepared: PreparedStatements = {
    insert_s256: ([s, c]) => stmts[s].bind(c.code_verifier, c.code_challenge),
    insert_webhook: ([s, w]) => stmts[s].bind(w.id, w.secret),
    insert_webhook_to_twitter: ([s, p]) =>
      stmts[s].bind(p.webhook_id, p.twitter_id),
    insert_twitter: ([s, tw]) => stmts[s].bind(tw.id, tw.username, tw.name),
    insert_twitter_token: ([s, tk]) =>
      stmts[s].bind(
        tk.twitter_id,
        tk.access_token,
        tk.vaild_until,
        tk.refresh_token
      ),
    delete_webhook: ([s, id]) => stmts[s].bind(id),
    get_webhook: ([s, id]) => stmts[s].bind(id),
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
  };
}

async function fetch_twitter_account_of_token(
  access_token: string
): Promise<TwitterAccount> {
  return (
    await (
      await oauth.protectedResourceRequest(
        access_token,
        "GET",
        new URL("https://api.twitter.com/2/users/me")
      )
    ).json<{ data: TwitterAccount }>()
  ).data;
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
    id: parseInt(random_hex(4), 16),
    secret: random_hex(16),
  };
  if (await ctx.sql.first(["insert_webhook", webhook])) {
    return webhook;
  } else {
    return new_webhook(ctx);
  }
}
function webhook_hex(w: Webhook) {
  return "0x" + w.id.toString(16).padStart(8, "0");
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

const state: string = "state";
async function twitter_auth(
  ctx: Context,
  redirect_uri: URL,
  state: string
): Promise<TwitterAccount | oauth.OAuth2Error> {
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
  const token = await oauth.processAuthorizationCodeOAuth2Response(
    twitter_auth_server,
    ctx.twitter,
    response
  );
  console.log(token);
  if (oauth.isOAuth2Error(token)) return token;
  console.log("Access Token Response", token);
  if (!token.refresh_token) return { error: "missing refresh_token" };

  // const params = new URLSearchParams();
  // params.append("code", code);
  // params.append("grant_type", "authorization_code");
  // params.append("client_id", ctx.twitter.client_id);
  // params.append("redirect_uri", callback);
  // params.append("code_verifier", "challenge");

  // const tokens = await (
  //   await fetch("https://api.twitter.com/2/oauth2/token", {
  //     method: "POST",
  //     headers: {
  //       "Content-Type": "application/x-www-form-urlencoded",
  //       Authorization: twitter_basic(ctx),
  //     },
  //     body: params,
  //   })
  // ).json<{
  //   token_type: string;
  //   expires_in: number;
  //   access_token: string;
  //   scope: string;
  //   refresh_token: string;
  // }>();
  // console.log("auth", tokens);

  const twitter_account: TwitterAccount = await fetch_twitter_account_of_token(
    token.access_token
  );
  await ctx.sql.batch([
    ["insert_twitter", twitter_account],
    [
      "insert_twitter_token",
      {
        twitter_id: twitter_account.id,
        access_token: token.access_token,
        vaild_until: token.expires_in
          ? Date.now() + token.expires_in * 60
          : undefined,
        refresh_token: token.refresh_token,
      },
    ],
  ]);
  return twitter_account;
}

// async function refresh(
//   username: string,
//   token: string,
//   ctx: Context
// ): Promise<string> {
//   const params = new URLSearchParams();
//   params.append("grant_type", "refresh_token");
//   params.append("client_id", ctx.twitter.client_id);
//   params.append("refresh_token", token);

//   const res = await gatherResponse(
//     await fetch("https://api.twitter.com/2/oauth2/token", {
//       method: "POST",
//       headers: {
//         "Content-Type": "application/x-www-form-urlencoded",
//         Authorization: twitter_basic(ctx),
//       },
//       body: params,
//     })
//   );

//   const data = JSON.parse(res) as {
//     token_type: string;
//     expires_in: number;
//     access_token: string;
//     scope: string;
//     refresh_token: string;
//   };

//   console.log("refresh", res);
//   if (data.access_token && data.expires_in && data.refresh_token) {
//     env.mi2tw_Auth.put(
//       username,
//       JSON.stringify({
//         access_token: data.access_token,
//         vaild_until: Date.now() + data.expires_in * 60,
//         refresh_token: data.refresh_token,
//       })
//     );
//   } else {
//     throw new Error("Refresh Failed");
//   }

//   return data.access_token;
// }

// async function tweet(
//   env: Env,
//   uid: string,
//   server: string,
//   note: Note
// ): Promise<void> {
//   if (
//     note.renoteId == undefined &&
//     note.replyId == undefined &&
//     note.cw == undefined &&
//     note.localOnly != true &&
//     note.text // && /\#mi2tw/.test(note.text)
//   ) {
//     console.log("tw", uid);
//     const val = await env.mi2tw_Auth.get(uid);
//     if (!val) return;
//     console.log("val", val);
//     const res = JSON.parse(val) as {
//       access_token: string;
//       vaild_until: number;
//       refresh_token: string;
//     };
//     const token =
//       res.vaild_until - 1000 < Date.now()
//         ? await refresh(uid, res.refresh_token, env)
//         : res.access_token;
//     // const token = await refresh(uid, res.refresh_token, env);

//     console.log(
//       "tweet",
//       await gatherResponse(
//         await fetch("https://api.twitter.com/2/tweets", {
//           method: "POST",
//           headers: {
//             "Content-type": "application/json",
//             Authorization: `Bearer ${token}`,
//           },
//           body: JSON.stringify({
//             text: `${note.text}\n\n${server}/notes/${note.id}`,
//           }),
//         })
//       )
//     );
//   }
// }

function twitter_basic(ctx: Context) {
  return (
    "Basic " + btoa(`${ctx.twitter.client_id}:${ctx.twitter.client_secret}`)
  );
}

export default new Hono<{ Bindings: Env }>({ strict: false })
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
    const twitter: TwitterAccount | oauth.OAuth2Error = await twitter_auth(
      ctx,
      no_search(c.req.url),
      state
    );
    if (((t): t is oauth.OAuth2Error => true)(twitter)) {
      console.log("twitter auth failed", twitter);
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
    // redirect_uri.searchParams.set("hex", hex);
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
  });
// .post("/:hex", async (c) => {
//   const { hex } = c.req.param();
//   const secret = c.req.header("x-misskey-hook-secret");
//   if (hex) {
//     const payload = await c.req.json<WebhookPayload>();
//     if (payload.type == "note") {
//       await tweet(c.env, hex, payload.server, payload.body.note);
//     }
//   }
// });
