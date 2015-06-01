# KOAuth - OAuth 1.0a Provider & Consumer Library in Scala

This library aids calculations according to the [OAuth 1.0a](http://oauth.net/core/1.0a/)
specifications for both HTTP server and client.

* Provider library: Verifying and responding to HTTP requests according to specifications.
* Consumer library: Complementing HTTP requests to be sent with OAuth parameters.

There are examples of [how to use this library here](https://github.com/kovacshuni/koauth-samples).
There are both for consumer, provider, Scala and Java.
I recommend trying them out, it will help you more than any readme.

## Quick how to

```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"

libraryDependencies += "com.hunorkovacs" %% "koauth" % "1.0.1-SNAPSHOT"
```

### Consumer (Spray)

```scala
private def sign(request: HttpRequest, token: String, secret: String) = {
  consumer.createOauthenticatedRequest(KoauthRequest(request.method.value, request.uri.toString(), None, None),
      ConsumerKey, ConsumerSecret, token, secret) map { requestWithInfo =>
    request.withHeaders(RawHeader("Authorization", requestWithInfo.header))
  }
}

sign(pipelining.Get(lastTweetUrl)).flatMap(pipeline(_))
```

There are also `consumer.createRequestTokenRequest()` and `consumer.createAccessTokenRequest()` functions at your disposal.

### Provider (Scalatra)

```scala
get("/me") {
  val response =
    requestMapper.map(request) flatMap { koauthRequest =>
      provider.oauthenticate(koauthRequest)
    } map {
      case Left(result) => result match {
        case ResponseUnauthorized(body) => Unauthorized("You are treated as a guest.\n" + body)
        case ResponseBadRequest(body) => BadRequest("You are treated as a guest.\n" + body)
      }
      case Right(username) => Ok("You are " + username + ".")
    }
  Await.result(response, 4 seconds)
}
```

Yes, you will need a `RequestMapper` that turns your HTTP framework's incoming request to a `KoauthRequest`:

```scala
override def map(source: HttpServletRequest) =
  Future(KoauthRequest(source.getMethod, source.getRequestURL.toString, Option(source.getHeader("Authorization")), None))
```

and a persistence to be able to create a provider:

```scala
  val ec = ExecutionContext.Implicits.global
  val provider = ProviderServiceFactory.createProviderService(new MyExampleMemoryPersistence(ec), ec)
```

### Request/response mapping

There are also `provider.requestToken()`, `provider.authorizeRequestToken()` and `provider.accessToken()` functions defined
to aid you. You should see [the example projects](https://github.com/kovacshuni/koauth-samples), how to map your requests, 
resonses, and how to handle authorization.

### Persistence

When creating a `ProviderService`, you'll need to define your `Persistence` for it.
This library exposes an interface (trait) that you must implement and connect to your database in your own way.
To store your tokens & nonces, etc, you could use any kind of underlying database as you whish.
There is an *in-memory* implementation provided, as a guideline, good for practice, not for production use.

There is a test class, `PersistenceSpec`, that could help you verify if your implementation is correct.
It's not an exhausting suite but gives you a basic acknowledgement whether your Persistence is fine.
Write your test like this:

```scala
class YourPersistenceSpec extends PersistenceSpec(new YourPersistence(ExecutionContext.Implicits.global))
```

### Design your controller:

Define the HTTP paths required by OAuth 1.0a

* POST to /oauth/request-token
* POST to /oauth/access-token

```scala
post("/oauth/request-token") {
  Await.result(mapCallMap(provider.requestToken), 4 seconds)
}

post("/oauth/access-token") {
  Await.result(mapCallMap(provider.accessToken), 4 seconds)
}

private def mapCallMap(f: KoauthRequest => Future[KoauthResponse]) = {
  requestMapper.map(request)
    .flatMap(f)
    .flatMap(responseMapper.map)
}
```

(example was written in Scalatra)

## Authorization

*Authorizing* a Request Token is done in a custom way and it's not incorporated in this lib as
it is not incorporated in the Oauth 1.0a specs. This is usually done by sending a request that
contains a username, password and a request token key and the server verifying that and assigning
a verifier for the respective token if everything was correct. But using a password is not necessary.
One could authorize with facebook for example: if a valid facebook access token could be acquired,
one could use that to authorize a request token. This method is totally in your hands.
There is an example with a super-simple password-way in the [koauth-samples](https://github.com/kovacshuni/koauth-samples).

## Asynchronous

*Futures* were used trying to make the every call independent and be able to run in parallel.
You will need to supply an `ExecutionContext` for the provider and consumer services:

```scala
val ec = play.api.libs.concurrent.Execution.Implicits.defaultContext
val consumer = new ConsumerService(ec)
val provider = new ProviderService(persistence, ec)
```

## Java?

### Consumer (javax.ws.rs HTTP client)

```java
private class LastTweetRoute implements Route {
    public Object handle(Request request, spark.Response response) throws Exception {
        String lastTweetUrl = "https://api.twitter.com/1.1/statuses/user_timeline.json?count=1&include_rts=1&trim_user=true";
        Invocation.Builder builder = http.target(lastTweetUrl).request();
        RequestWithInfo requestWithInfo = consumer.createOauthenticatedRequest(KoauthRequest.apply("GET",
                        lastTweetUrl, Option.<String>empty()),
                CONSUMER_KEY,
                CONSUMER_SECRET,
                accessToken.token(),
                accessToken.secret());
        Invocation invocation = builder.header("Authorization", requestWithInfo.header()).buildGet();

        Response twResponse = invocation.invoke();

        System.out.println("Response: HTTP " + twResponse.getStatus());
        String body = twResponse.readEntity(String.class);
        System.out.println(body);
        return body;
    }
}
```

### Provider (Spark framework)

```java
private class MeRoute implements Route {
    public Object handle(Request request, Response response) throws Exception {
        KoauthRequest koauthRequest = requestMapper.map(request);
        Either<KoauthResponse, String> authentication = provider.oauthenticate(koauthRequest);
        if (authentication.isLeft()) {
            KoauthResponse left = authentication.left().get();
            if (left.getClass().equals(ResponseUnauthorized.class)) {
                response.status(401);
                return "You are treated as a guest.\n" + ((ResponseUnauthorized) left).body();
            } else {
                response.status(400);
                return "You are treated as a guest.\n" + ((ResponseBadRequest) left).body();
            }
        } else {
            String username = authentication.right().get();
            return "You are " + username + ".";
        }
    }
}
```

Too much code for a readme, [see the examples](https://github.com/kovacshuni/koauth-samples)!

## Notes

In a RESTful environment, and with Oauth 1.0a, every request is authenticated, so it's usually a
good practice to have your authentication come in as either a filter or a separate proxy application.
So instead of the _/me_ method that i defined above, you should have a proxy parses every _/*_ request, and just verifies
if the request was signed, and if it could be authenticated correctly, attaches this info in a header and passes it on
to the real app. There is another example, that does this:
[koauth-sample-proxy-finagle](https://github.com/kovacshuni/koauth-sample-proxy-finagle)

Please read [the documentation](http://oauth.net/core/1.0a/) of Oauth 1.0a, understand the process
of obtaining an access token and using one for authenticating requests. Take your time. It's not easy for the first read.
Implement your controllers for the specification's steps and use the service's methods.

* For consumers, the Signature Base string is exposed to help you debug unhappy situations.
* Always track the [releases from GitHub](https://github.com/kovacshuni/koauth/releases) and [Maven Central](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22koauth-sync_2.11%22). Pre-built nightly/snapshot versions are not available yet at Maven Central, the master branch is work-in-progress, don't rely on it too much.
* I'm planning to implement all this for OAuth 2.0 in the far future.

## Contributing

Just create a pull-request, we'll discuss it, i'll try to be quick.

Building and testing locally:

```
git clone https://github.com/kovacshuni/koauth.git
cd koauth
sbt
compile
test
```

Publishing (mostly for me :) )
[help](http://www.scala-sbt.org/0.13/docs/Using-Sonatype.html)

```
sbt
show */*:pgpSecretRing
# rm that file
show */*:pgpPublicRing
# rm that file
set pgpReadOnly := false
pgp-cmd gen-key
pgp-cmd send-key kovacshuni@yahoo.com hkp://pool.sks-keyservers.net
# make sure this contains your credentials ~/.sbt/0.13/sonatype.sbt
publishSigned
```

## Owner

Hunor Kovács  
kovacshuni@yahoo.com  
[hunorkovacs.com](http://www.hunorkovacs.com)

## Licence

Licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0) .
