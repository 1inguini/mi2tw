import { D1Database } from "@cloudflare/workers-types";
import { Hono, HonoRequest } from "hono";
import { html } from "hono/html";
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

type Context = Readonly<{
  req: HonoRequest;
  sql: Sql;
  twitter: Readonly<{
    client_id: string;
    client_secret: string;
  }>;
}>;

function context(req: HonoRequest, env: Env): Context {
  return {
    req,
    sql: prepareSql(env.db),
    twitter: {
      client_id: env.twitter_client_id,
      client_secret: env.twitter_client_secret,
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

// // D1 schema
//
// CREATE TABLE webhook (
//   webhook_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
//   hashed_secret TEXT NOT NULL
//   salt TEXT NOT NULL,
// );
//
// CREATE TABLE webhook_to_twitter (
//   webhook_id INTEGER NOT NULL
//   twitter_id INTEGER NOT NULL
//   FOREIGN KEY (webhook) REFERENCES webook (id)
//     ON UPDATE CASCADE
//     ON DELETE CASCADE,
//   FOREIGN KEY (twitter_id) REFERENCES twitter (twitter_id)
//     ON UPDATE CASCADE
//     ON DELETE CASCADE
// );
//
// CREATE TABLE twitter (
//   twitter_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
//   twitter_username TEXT NOT NULL,
//   twitter_name TEXT,
// );
//
// CREATE TABLE twitter_token (
//   twitter_token_id INTEGER NOT NULL UNIQUE PRIMARY KEY,
//   twitter_id INTEGER NOT NULL
//   access_token TEXT,
//   vaild_until INTEGER,
//   refresh_token TEXT NOT NULL,
//   FOREIGN KEY (twitter_id) REFERENCES twitter (twitter_id)
//     ON UPDATE CASCADE
//     ON DELETE CASCADE
// );

type RowId = number;

type Webhook = {
  id: RowId;
  secret: string;
};

type TwitterToken = {
  twitter_id: RowId;
  access_token: string;
  vaild_until: number;
  refresh_token: string;
};

type StatementSigniture<P, R = RowId> = { param: P; return: R };

type PreparedStatementsSigniture = Readonly<{
  insert_webhook: StatementSigniture<Webhook>;
  insert_twitter: StatementSigniture<TwitterAccount>;
  insert_twitter_token: StatementSigniture<TwitterToken>;
}>;

type PreparedStatements = {
  [S in keyof PreparedStatementsSigniture]: (
    _: PreparedStatementsSigniture[S]["param"]
  ) => D1PreparedStatement;
};

type Proxy<T> = void;

type Query<S extends keyof PreparedStatementsSigniture> = {
  statement: S;
  param: PreparedStatementsSigniture[S]["param"];
};

type Sql = Readonly<{
  batch<T = unknown>(
    queries: Query<keyof PreparedStatements>[]
  ): Promise<D1Result<T>[]>;
  first<S extends keyof PreparedStatements>(
    query: Query<S>
  ): Promise<
    PreparedStatementsSigniture[(typeof query)["statement"]]["return"] | null
  >;
}>;

function prepareSql(db: D1Database): Sql {
  const stmts = {
    insert_webhook: db.prepare(
      `INSERT INTO webhook(webhook_id, hashed_secret, salt)
          VALUES(?1, ?2, ?3)
          RETURNING webhook_id LIMIT 1`
    ),
    insert_twitter: db.prepare(
      `INSERT INTO twitter(twitter_id, twitter_username, twitter_name)
          VALUES(?1, ?2, ?3)
          RETURNING twitter_id LIMIT 1`
    ),
    insert_twitter_token: db.prepare(
      `INSERT INTO twitter_token(twitter_id, access_token, valid_until, refresh_token)
          VALUES(?1, ?2, ?3, ?4)
          RETURNING twitter_token_id LIMIT 1`
    ),
  };
  const prepared: {
    [S in keyof PreparedStatementsSigniture]: (
      _: PreparedStatementsSigniture[S]["param"]
    ) => D1PreparedStatement;
  } = {
    insert_webhook: (w: Webhook) => stmts.insert_webhook.bind(w.id, w.secret),
    insert_twitter: (tw: TwitterAccount) =>
      stmts.insert_twitter.bind(tw.id, tw.username, tw.name),
    insert_twitter_token: (tk: TwitterToken) =>
      stmts.insert_twitter.bind(
        tk.twitter_id,
        tk.access_token,
        tk.vaild_until,
        tk.refresh_token
      ),
  };
  return {
    batch: (queries) =>
      db.batch(
        queries.map(
          <S extends keyof PreparedStatementsSigniture>(q: Query<S>) =>
            prepared[q.statement](q.param)
        )
      ),
    first: (query) => prepared[query.statement](query.param).first(),
  };
}

async function gatherResponse(response: Response) {
  const { headers } = response;
  const contentType = headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return JSON.stringify(await response.json());
  }
  return response.text();
}

interface TwitterAccount {
  id: number;
  username: string;
  name: string;
}

async function fetch_twitter_account_of_token(
  access_token: string
): Promise<TwitterAccount> {
  return await (
    await (
      await fetch("https://api.twitter.com/2/users/me", {
        method: "GET",
        headers: {
          "Content-type": "application/json",
          Authorization: `Bearer ${access_token}`,
        },
      })
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
  if (await ctx.sql.first("insert_webhook", [webhook])) {
    return webhook;
  } else {
    return new_webhook(ctx);
  }
}

async function auth(
  ctx: Context,
  callback: string,
  code: string
): Promise<TwitterAccount> {
  const params = new URLSearchParams();
  params.append("code", code);
  params.append("grant_type", "authorization_code");
  params.append("client_id", ctx.twitter.client_id);
  params.append("redirect_uri", callback);
  params.append("code_verifier", "challenge");

  const tokens = await (
    await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: twitter_basic(ctx),
      },
      body: params,
    })
  ).json<{
    token_type: string;
    expires_in: number;
    access_token: string;
    scope: string;
    refresh_token: string;
  }>();
  console.log("auth", tokens);

  const twitter_account: TwitterAccount = await fetch_twitter_account_of_token(
    tokens.access_token
  );
  await ctx.sql.batch((s) => [
    s.insert_twitter([twitter_account]),
    s.insert_twitter_token([
      {
        twitter_id: twitter_account.id,
        access_token: tokens.access_token,
        vaild_until: Date.now() + tokens.expires_in * 60,
        refresh_token: tokens.refresh_token,
      },
    ]),
  ]);
  return twitter_account;
}

async function refresh(
  username: string,
  token: string,
  ctx: Context
): Promise<string> {
  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", ctx.twitter.client_id);
  params.append("refresh_token", token);

  const res = await gatherResponse(
    await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: twitter_basic(ctx),
      },
      body: params,
    })
  );

  const data = JSON.parse(res) as {
    token_type: string;
    expires_in: number;
    access_token: string;
    scope: string;
    refresh_token: string;
  };

  console.log("refresh", res);
  if (data.access_token && data.expires_in && data.refresh_token) {
    env.mi2tw_Auth.put(
      username,
      JSON.stringify({
        access_token: data.access_token,
        vaild_until: Date.now() + data.expires_in * 60,
        refresh_token: data.refresh_token,
      })
    );
  } else {
    throw new Error("Refresh Failed");
  }

  return data.access_token;
}

async function tweet(
  env: Env,
  uid: string,
  server: string,
  note: Note
): Promise<void> {
  if (
    note.renoteId == undefined &&
    note.replyId == undefined &&
    note.cw == undefined &&
    note.localOnly != true &&
    note.text // && /\#mi2tw/.test(note.text)
  ) {
    console.log("tw", uid);
    const val = await env.mi2tw_Auth.get(uid);
    if (!val) return;
    console.log("val", val);
    const res = JSON.parse(val) as {
      access_token: string;
      vaild_until: number;
      refresh_token: string;
    };
    const token =
      res.vaild_until - 1000 < Date.now()
        ? await refresh(uid, res.refresh_token, env)
        : res.access_token;
    // const token = await refresh(uid, res.refresh_token, env);

    console.log(
      "tweet",
      await gatherResponse(
        await fetch("https://api.twitter.com/2/tweets", {
          method: "POST",
          headers: {
            "Content-type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            text: `${note.text}\n\n${server}/notes/${note.id}`,
          }),
        })
      )
    );
  }
}

async function revoke(uid: string, env: Env) {
  const res = await env.mi2tw_Auth.get(uid);
  if (res) {
    const params = new URLSearchParams();
    params.append("client_id", env.twitter_client_id);
    params.append("token", JSON.parse(res).access_token);

    await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params,
    });

    env.mi2tw_Auth.delete(uid);
  }
}

function twitter_basic(ctx: Context) {
  return (
    "Basic " + btoa(`${ctx.twitter.client_id}:${ctx.twitter.client_secret}`)
  );
}

const secret: string = "secret";

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
    return c.redirect("/");
  })
  .get("/:hex", async (c) => {
    const ctx = context(c.req, c.env);
    const url: URL = new URL(c.req.url);
    const state: string = "state"; // CSRF?のなんからしい
    return c.html(
      <html>
        <head>
          <meta charset="utf-8" />
        </head>
        <body>
          <a
            href={`https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${ctx.twitter.client_id}&redirect_uri=${url.origin}${url.pathname}/callback&scope=offline.access%20users.read%20tweet.read%20tweet.write&state=${state}&code_challenge=challenge&code_challenge_method=S256`}
          >
            ここで認可
          </a>
        </body>
      </html>
    );
  })
  .get("/:hex/callback", async (c) => {
    const ctx = context(c.req, c.env);
    const { hex } = c.req.param();
    const { code } = c.req.query();
    const origin: string = new URL(c.req.url).origin;
    const callback: string = origin + c.req.path;
    if (code) {
      const twitter: TwitterAccount = await auth(ctx, callback, code);
      if (twitter) {
        return c.html(
          <html>
            <head>
              <meta charset="utf-8" />
            </head>
            <body>
              これをMisskey側WebhookのURLに入力:
              <input type="text" readonly value={`${origin}/${hex}`}></input>
              <br />
              これをMisskey側WebhookのSecretに入力:
              <input
                id="uid"
                type="text"
                readonly
                value={webhook.secret}
              ></input>
              <br />
              <a href={`${origin}/${hex}/revoke`}>
                <button>アクセスキーを削除</button>
              </a>
            </body>
          </html>
        );
      }
    }
    return c.html("<meta charset='utf-8'>認証に失敗しました");
  })
  .get("/:hex/revoke", async (c) => {
    const { hex } = c.req.param();
    await revoke(hex, c.env);
    return c.html("<meta charset='utf-8'>削除しました");
  })
  .post("/:hex", async (c) => {
    const { hex } = c.req.param();
    const secret = c.req.header("x-misskey-hook-secret");
    if (hex) {
      const payload = await c.req.json<WebhookPayload>();
      if (payload.type == "note") {
        await tweet(c.env, hex, payload.server, payload.body.note);
      }
    }
  });
