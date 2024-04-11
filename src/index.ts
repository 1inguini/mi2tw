import { ExecutionContext, KVNamespace } from "@cloudflare/workers-types";
import { toString } from "misskey-js/built/dts/acct";
import type { Note, User } from "misskey-js/built/esm/entities";

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

async function refresh(key: string, token: string, env: Env): Promise<string> {
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
      key,
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
    })).json<{ data: { "id": number; "name": string; "username": string } }>();

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

async function auth(
  endpoint: URL,
  code: string,
  env: Env,
): Promise<Response> {
  const hook = new URL(endpoint.origin + endpoint.pathname);
  const params = new URLSearchParams();
  params.append("code", code);
  params.append("grant_type", "authorization_code");
  params.append("client_id", env.client_id);
  params.append("redirect_uri", hook.href);
  params.append("code_verifier", "challenge");

  const data = await (await fetch("https://api.twitter.com/2/oauth2/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Authorization": `Basic ${btoa(`${env.client_id}:${env.client_secret}`)}`,
    },
    body: params,
  })).json<
    {
      token_type: string;
      expires_in: number;
      access_token: string;
      scope: string;
      refresh_token: string;
    }
  >();

  console.log("auth", JSON.stringify(data));

  if (data.access_token) {
    const twitter: TwitterAccount =
      (await (await fetch("https://api.twitter.com/2/users/me", {
        method: "GET",
        headers: {
          "Content-type": "application/json",
          "Authorization": `Bearer ${data.access_token}`,
        },
      })).json<{ data: TwitterAccount }>()).data;

    // let uid = await env.mi2tw_Uid.get(user.data.id.toString());
    // if (uid == undefined) {
    //   uid = crypto.randomUUID();
    //   await env.mi2tw_Uid.put(user.data.id.toString(), uid);
    // }
    await env.mi2tw_Auth.put(
      twitter.id.toString(),
      JSON.stringify({
        "access_token": data.access_token,
        "vaild_until": Date.now() + data.expires_in * 60,
        "refresh_token": data.refresh_token,
      }),
    );

    const secret = crypto.randomUUID();
    const result = new Response(
      `<meta charset='utf-8'>これをMisskey側WebhookのURLに入力: <input type="text" readonly value="${hook}"></input><br>これをMisskey側WebhookのSecretに入力: <input id="uid" type="text" readonly value="${secret}"></input><br><a href="./revoke?uid=${twitter.id.toString()}"><button>アクセスキーを削除</button></a>`,
      { headers: [["Content-type", "text/html"]] },
    );
    return result;
  } else {
    return new Response("認証に失敗しました");
  }
}

async function tweet(
  server: string,
  note: Note,
  key: string,
  env: Env,
): Promise<void> {
  if (
    note.renoteId == undefined &&
    note.replyId == undefined && note.cw == undefined &&
    note.localOnly != true && note.text // && /\#mi2tw/.test(note.text)
  ) {
    // console.log("tw", key);
    // const key = await env.mi2tw_Auth.get(key);
    console.log("key", key);
    if (!key) return;
    const res = JSON.parse(key) as {
      "access_token": string;
      "vaild_until": number;
      "refresh_token": string;
    };
    const token = res.vaild_until - 1000 < Date.now()
      ? await refresh(key, res.refresh_token, env)
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

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const endpoint: URL = new URL(request.url);

    if (request.method === "POST") {
      const secret = request.headers.get("x-misskey-hook-secret");
      const key = new URLPattern(`/:twitter_username`).exec(
        endpoint,
      );
      if (key) {
        const payload = await request.json<WebhookPayload>();
        if (payload.type == "note") {
          await tweet(
            payload.server,
            payload.body.note,
            key.pathname.groups.twitter_username,
            env,
          );
        }
        return new Response();
      }
    } else if (endpoint.pathname === "/callback") {
      const code = endpoint.searchParams.get("code");
      if (code) {
        return await auth(endpoint, code, env);
      }
    } else if (endpoint.pathname === "/revoke") {
      const uid = endpoint.searchParams.get("uid");
      if (uid) {
        await revoke(uid, env);
        return new Response("削除しました");
      }
    }

    const twAuth: string =
      `https://twitter.com/i/oauth2/authorize?response_type=code&client_id=${env.client_id}&scope=offline.access%20users.read%20tweet.read%20tweet.write&state=state&code_challenge=challenge&code_challenge_method=plain`;
    const res = new Response(
      `<meta charset='utf-8'>
      <body>
        <h1>MisskeyのWebhook使って投稿をTwitterに転送するやつ</h1><br>
        (ローカル限定でない、リプライでない、リノートでない、CWもついてない投稿のみ)<br>
        <label for="server">サーバーのドメイン: </label><input id="server" type="text" value="misskey.io" required />
        <input id="auth" type="button" value="ドメインを入力してここで認証" />
        <script>
          document.getElementById('auth').addEventListener('click', (e) => {
            location.href =
              \`${twAuth}&redirect_uri=${new URL(
        "callback/",
        endpoint,
      )}?server=\${document.getElementById('server').value}\`;
          });
        </script>
      </body>`,
      { headers: [["Content-type", "text/html"]] },
    );
    return res;
  },
};
