# KOAuth Sync - OAuth 1.0a Provider & Consumer Library in Scala

**Same as [koauth](https://github.com/kovacshuni/koauth) but not in asynchronous mode.
From the topmost function definitions and interfaces Futures were removed.**

This library aids calculations according to the [OAuth 1.0a](http://oauth.net/core/1.0a/)
specifications for both HTTP server and client.

* Provider library: Verifying and responding to HTTP requests according to specifications.
* Consumer library: Complementing HTTP requests to be sent with OAuth parameters. 

## Quick how to

### Dependencies

koauth is available on Maven Central. Add the following repository and dependency in your `build.sbt`:

```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"

libraryDependencies += "com.hunorkovacs" %% "koauth-sync" % "1.0.0"
```
### Persistence

**One must provide an implementation for the `Persistence` trait**. Oauth 1.0a works with
tokens & nonces, so this library exposes an interface (trait) that you must implement and connect
to your database in your own way. You could use any kind of underlying database as you whish,
just need to respect the signature of the `Persistence` traits methods and the lib will call them.

There is one implementation provided by the koauth library itself, as a guideline
but it is *in-memory*, and all the kept data is lost after stopping the application.

You then pass your persistence as argument when creating your provider service:

```scala
val persistence = new ExampleMemoryPersistence()
val providerService = ProviderServiceFactory.createProviderService(persistence, executionContext)
```

There is a test class, `PersistenceSpec`, that could help you verify if your implementation is correct.
It's not an exhausting suite but gives you a basic acknowledgement whether your Persistence is fine.
Write your test like this:

```scala
class YourPersistenceSpec extends PersistenceSpec(new YourPersistence(ExecutionContext.Implicits.global))
```

### Request mapping

**Implement the `RequestMapper` and `ResponseMapper`** as needed to map your HTTP client's
request and response types to koauth lib's independent types.

```scala
class NettyRequestMapper(private val ec: ExecutionContext) extends RequestMapper[HttpRequest] {

  implicit private val implicitEc = ec

  override def map(source: HttpRequest): KoauthRequest = {
    val method = source.getMethod.getName
    val queryStringDecoder = new QueryStringDecoder(source.getUri)
    val urlWithoutParams = "http://" + source.headers.get(HttpHeaders.Names.HOST) + queryStringDecoder.getPath
    val authHeader = Option(source.headers.get(AUTHORIZATION))
    val urlParams = queryStringDecoder.getParameters.asScala.mapValues(_.get(0)).toList
    val bodyParams = List.empty

    KoauthRequest(method, urlWithoutParams, authHeader, urlParams, bodyParams)
  }
}

class OauthResponseMapper(private val ec: ExecutionContext) extends ResponseMapper[Result] {

  implicit private val implicitEc = ec

  override def map(source: KoauthResponse): Result = {
    source match {
      case ResponseOk(body) => Ok(body)
      case ResponseUnauthorized(body) => Unauthorized(body)
      case ResponseBadRequest(body) => BadRequest(body)
      case _ => NotImplemented
    }
  }
}

object OauthController extends Controller {
  /**
   * Mapped to POST /oauth/request-token
   */
  def requestToken = Action.async { request =>
    requestMapper.map(request)
      .flatMap(oauthProvider.requestToken)
      .flatMap(responseMapper.map)
  }
}
```

## Provider

There is also an sample project: [koauth-sample-play](https://github.com/kovacshuni/koauth-sample-play)
that is using [Play Framework](http://www.playframework.com/). This is something you can most easily follow.
Worth to use as the starting point, because it is easier to understand.

In a RESTful environment, and with Oauth 1.0a, every request is authenticated, so it's usually a
good practice to have your authentication come in as either a filter or a separate proxy application.
There is another example, that does this:
[koauth-sample-proxy-finagle](https://github.com/kovacshuni/koauth-sample-proxy-finagle)

### Define the HTTP paths required by OAuth 1.0a

* POST to /oauth/request-token
* POST to /oauth/access-token

Your exact paths may differ, but for a proper OAuth 1.0a you will need to define at least two HTTP endpoints.
You will probably want one or more endpoints for authorizing Request Tokens, but that is not a necessity for
this library as even the Oauth1.0a specs say that is custom and for you to figure out.

There are service functions defined in `ProviderService` for every necessary step in OAuth 1.0a.
Please read [the documentation](http://oauth.net/core/1.0a/) of Oauth 1.0a, understand the process
of obtaining an access token and using one for authenticating requests. Implement your controllers
for the specification's steps and use the service's methods.

## Step By Step Example - Consumer

How to build HTTP requests that should be OAuth signed, using this library.

The consumer service doesn't need a database, it just signs requests on the fly.
You create one by using the constructor:

```scala
val ec = play.api.libs.concurrent.Execution.Implicits.defaultContext
new DefaultConsumerService(ec)
```

Then you can just simply sign requests by calling the service methods:

```
val requestWithInfo = consumerService.createOauthenticatedRequest(request, ....)
```

It will return you the request with completed nonce and other parameters, the Authorization header
you have to add to your request and the Signature Base string which could help you debug unhappy situations.
There are separate service methods for different types of Oauth 1.0a requests.

## Authorization

*Authorizing* a Request Token is done in a custom way and it's not incorporated in this lib as
it is not incorporated in the Oauth 1.0a specs. This is usually done by sending a request that
contains a username, password and a request token key and the server verifying that and assigning
a verifier for the respective token if everything was correct. But using a password is not necessary.
One could authorize with facebook for example: if a valid facebook access token could be acquired,
one could use that to authorize a request token. This method is totally in your hands.

## Asynchronous

*Futures* were used in the code, trying to make the every call independent to run in parallel.
You will need to supply an `ExecutionContext` for the provider and consumer services:

```scala
val persistence = ....
val ec = play.api.libs.concurrent.Execution.Implicits.defaultContext
val consumer = new ConsumerService(ec)
val provider = new ProviderService(persistence, ec)
```

## Contributing

Just create a pull-request, we'll discuss it, i'll try to be quick.

Building and testing locally:

```
git clone https://github.com/kovacshuni/koauth.git
cd koauth
git checkout sync
sbt
compile
test
```

Publishing (mostly for me :) )
[help] (http://www.scala-sbt.org/0.13/docs/Using-Sonatype.html)

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
