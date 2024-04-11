import { ExecutionContext, KVNamespace } from "@cloudflare/workers-types";
import { Hono } from "hono";
import type { Bindings } from "hono/types";
import { html, raw } from "hono/html";
import type { Note, User } from "misskey-js/built/esm/entities";
import { HtmlEscaped } from "hono/utils/html";

type WebhookPayload =
  & {
    server: string;
    hookId: string;
    userId: User["id"];
    eventId: string;
    createdAt: number;
  }
  & (
    | { type: "follow" | "followed" | "unfollow"; body: { user: User } }
    | { type: "note" | "reply" | "renote"; body: { note: Note } }
  );
// "mention" | "unfollow" | "follow" | "followed" | ;
type Env = {
  mi2tw_Auth: KVNamespace;
  mi2tw_Uid: KVNamespace;
  client_id: string;
  client_secret: string;
};

type MisskeyAccount = {
  server: string;
  id: string;
};

type TwitterAccount = {
  id: number;
  name: string;
  username: string;
};

type AccountAssociation = {
  twitter: TwitterAccount;
  misskey: MisskeyAccount;
};

async function gatherResponse(response: Response) {
  const { headers } = response;
  const contentType = headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return JSON.stringify(await response.json());
  }
  return response.text();
}

async function refresh(
  username: string,
  token: string,
  env: Env,
): Promise<string> {
  const params = new URLSearchParams();
  params.append("grant_type", "refresh_token");
  params.append("client_id", env.client_id);
  params.append("refresh_token", token);

  const res = await gatherResponse(
    await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": `Basic ${
          btoa(`${env.client_id}:${env.client_secret}`)
        }`,
      },
      body: params,
    }),
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
        "access_token": data.access_token,
        "vaild_until": Date.now() + data.expires_in * 60,
        "refresh_token": data.refresh_token,
      }),
    );
  } else {
    throw new Error("Refresh Failed");
  }

  return data.access_token;
}

async function revoke(uid: string, env: Env) {
  const res = await env.mi2tw_Auth.get(uid);
  if (res) {
    const user = await (await fetch("https://api.twitter.com/2/users/me", {
      method: "GET",
      headers: {
        "Content-type": "application/json",
        "Authorization": `Bearer ${JSON.parse(res).access_token}`,
      },
    })).json<{ data: TwitterAccount }>();

    env.mi2tw_Uid.delete(user.data.id.toString());

    const params = new URLSearchParams();
    params.append("client_id", env.client_id);
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

type Tokens = {
  token_type: string;
  expires_in: number;
  access_token: string;
  scope: string;
  refresh_token: string;
};

function basic(env: Env) {
  return "Basic " + btoa(`${env.client_id}:${env.client_secret}`);
}

async function auth(
  env: Env,
  callback: string,
  code: string,
): Promise<Tokens> {
  const params = new URLSearchParams();
  params.append("code", code);
  params.append("grant_type", "authorization_code");
  params.append("client_id", env.client_id);
  params.append("redirect_uri", callback);
  params.append("code_verifier", "challenge");

  const tokens = await (await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": basic(env),
    },
    body: params,
  })).json<Tokens>();

  console.log("auth", tokens);
  return tokens;
}

async function twitter_of_token(
  env: Env,
  access_token: string,
): Promise<TwitterAccount> {
  return (await (await fetch("https://api.twitter.com/2/users/me", {
    method: "GET",
    headers: {
      "Content-type": "application/json",
      "Authorization": `Bearer ${access_token}`,
    },
  })).json<{ data: TwitterAccount }>()).data;
}

async function save_tokens(
  env: Env,
  uid: string,
  tokens: Tokens,
): Promise<void> {
  // let uid = await env.mi2tw_Uid.get(user.data.id.toString());
  // if (uid == undefined) {
  //   uid = crypto.randomUUID();
  //   await env.mi2tw_Uid.put(user.data.id.toString(), uid);
  // }
  await env.mi2tw_Auth.put(
    uid,
    JSON.stringify({
      "access_token": tokens.access_token,
      "vaild_until": Date.now() + tokens.expires_in * 60,
      "refresh_token": tokens.refresh_token,
    }),
  );
}

async function tweet(
  env: Env,
  uid: string,
  server: string,
  note: Note,
): Promise<void> {
  if (
    note.renoteId == undefined &&
    note.replyId == undefined && note.cw == undefined &&
    note.localOnly != true && note.text // && /\#mi2tw/.test(note.text)
  ) {
    console.log("tw", uid);
    const val = await env.mi2tw_Auth.get(uid);
    if (!val) return;
    console.log("val", val);
    const res = JSON.parse(val) as {
      "access_token": string;
      "vaild_until": number;
      "refresh_token": string;
    };
    const token = res.vaild_until - 1000 < Date.now()
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
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({
            "text": `${note.text}\n\n${server}/notes/${note.id}`,
          }),
        }),
      ),
    );
  }
}

const secret: string = "secret";

export default new Hono<{ Bindings: Env }>({ strict: false })
  .get("/", async (c) => {
    const origin: string = new URL(c.req.url).origin;
    return c.html(
      html`<meta charset='utf-8'>
      <body>
        <h1>MisskeyのWebhook使って投稿をTwitterに転送するやつ</h1><br>
        (ローカル限定でない、リプライでない、リノートでない、CWもついてない投稿のみ)<br>
        <a href='https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${c.env.client_id}&redirect_uri=${origin}/callback&scope=offline.access%20users.read%20tweet.read%20tweet.write&state=state&code_challenge=challenge&code_challenge_method=plain'>ここで認証</a>
      </body>`,
    );
  })
  .get("/callback", async (c) => {
    const { code } = c.req.query();
    const origin: string = new URL(c.req.url).origin;
    const callback: string = origin + "/callback";
    if (code) {
      const tokens: Tokens = await auth(c.env, callback, code);
      const twitter: TwitterAccount = await twitter_of_token(
        c.env,
        tokens.access_token,
      );
      const uid: string = twitter.id.toString();
      await save_tokens(c.env, uid, tokens);

      if (twitter) {
        return c.html(html`<meta charset='utf-8'>
        これをMisskey側WebhookのURLに入力: <input type="text" readonly value="${origin}/webhook/${uid}}"></input><br />
        これをMisskey側WebhookのSecretに入力: <input id="uid" type="text" readonly value="${secret}"></input><br />
        <a href="${origin}/revoke/${uid}"><button>アクセスキーを削除</button></a>`);
      }
    }
    return c.html("<meta charset='utf-8'>認証に失敗しました");
  })
  .get("/revoke/:uid", async (c) => {
    const { uid } = c.req.param();
    await revoke(uid, c.env);
    return c.html("<meta charset='utf-8'>削除しました");
  })
  .post("/webhook/:uid", async (c) => {
    const { uid } = c.req.param();
    const secret = c.req.header("x-misskey-hook-secret");
    if (uid) {
      const payload = await c.req.json<WebhookPayload>();
      if (payload.type == "note") {
        await tweet(
          c.env,
          uid,
          payload.server,
          payload.body.note,
        );
      }
    }
  });
