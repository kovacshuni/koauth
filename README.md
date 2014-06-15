# KOauth - Asynchronous Scala Library for OAuth 1.0a

This library aids calculations according to the [Oauth 1.0a](http://oauth.net/core/1.0a/)
specifications for both HTTP server and client.

* Provider library: Verifying and responding to HTTP requests according to OAuth 1.0 specifications.
* Consumer library: Complementing HTTP requests to be sent with OAuth parameters. 

## Set up your project dependencies

If you're using SBT, clone this project, build and publish it to your local repository and
add to your project as a dependency.

Building and publishing locally:

```
git clone https://github.com/kovacshuni/koauth.git
cd koauth
sbt
compile
publish-local
```

I also don't understand yet all these versions of Scala and SBT and numbers concatenated to
artifact names with underscores and the single/double percent stuff, so i just hardcoded 2.11.

Add as dependency by editing your `build.sbt` and adding the following:

```scala
libraryDependencies ++= Seq(
  "com.hunorkovacs" % "koauth_2.11" % "1.0"
)
```

Or if you want to be on the bleeding edge using snapshots:

```scala
libraryDependencies ++= Seq(
  "com.hunorkovacs" % "koauth_2.11" % "1.0-SNAPSHOT"
)
```

koauth is available on Maven Central. No it's not. Not yet. But i'll try to publish it soon.

```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"
```

or 

```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/snapshots/"
```

## Step By Step Example - Provider

How to integrate OAuth verification in your REST API server, using this library.

There is also an sample project: [koauth-sample-play](https://github.com/kovacshuni/koauth-sample-play)
that you can most easily follow. It is using [Play Framework](http://www.playframework.com/) 2.2.2
as web framework, [MongoDB](http://www.mongodb.org/) with [ReactiveMongo](http://reactivemongo.org/)
to save client credentials and other details. Worth to use as the starting point, because it is
easier to understand.

### Mapping your HTTP requests and responses.

## Step By Step Example - Consumer

How to build HTTP requests that should be OAuth signed, using this library.

todo write this readme part
