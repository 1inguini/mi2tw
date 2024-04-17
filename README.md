# mi2tw

~~`denoflare push src/index.ts --name mi2tw --text-binding 'client_id:<twitterのApi v2のclient id>' --text-binding 'client_secret:<twitterのApi v2のclient secret>' --kv-namespace-binding 'mi2tw_Auth:<Cloudflare KVのid>' --kv-namespace-binding 'mi2tw_Uid:<Cloudflare KVのid>'` でCloudflare Workersにデプロイ~~
普通にWrangler2でデプロイ

「ここで認証」を押して言われたとおりにmisskeyに投稿を通知するwebhookを登録

## <https://github.com/m-hayabusa/mi2tw>との違い

* ~~[deno](https://deno.com/), [denoflare](https://denoflare.dev)対応~~
* おそらく削除されてたBasic認証?のコードを復元
* #mi2tw とタグ付けされてなくても再投稿
* ツイートにノートのリンクをつけて投稿する
* 使うKVを一つに
* Honoを使う
* Cloudflare KVではなくCloudflare D1(RDBMS)を使う
* TODO: twitterの認可フローのcode_challenge_methodをplainではなくS256に
