# KOauth - Asynchronous Scala Library for OAuth 1.0a

This library aids calculations according to the [Oauth 1.0a](http://oauth.net/core/1.0a/)
specifications for both HTTP server and client.

* Provider library: Verifying and responding to HTTP requests according to OAuth 1.0 specifications.
* Consumer library: Complementing HTTP requests to be sent with OAuth parameters. 

## Step By Step Example - Provider

How to integrate OAuth verification in your REST API server, using this library.

There is also an sample project: [koauth-sample-play](https://github.com/kovacshuni/koauth-sample-play)
that you can most easily follow. It is using Play Framework 2.2.2 a web framework,
MongoDB with ReactiveMongo to save client credentials and other details. Worth to use
as starting point because it's easier to understand.

### Set up your project dependencies

If you're using SBT, clone this project, build and publish it to your local repository.

```sbt
cd koauth
sbt
compile
publish-local
```

koauth is available on Maven Central. No it's not. Not yet. But i'll try to publish it soon.
I also don't understand yet all these versions of Scala and SBT and numbers concatenated to
artifact names with underscores and the single/double percent stuff, so i just hardcoded 2.11.

Edit your `build.sbt` and add the following:

```scala
resolvers += "Sonatype Releases" at "https://oss.sonatype.org/content/repositories/releases/"

libraryDependencies ++= Seq(
  "com.hunorkovacs" % "koauth_2.11" % "1.0"
)
```

Or if you want to be on the bleeding edge using snapshots:

```scala
resolvers += "Sonatype Snapshots" at "https://oss.sonatype.org/content/repositories/snapshots/"

libraryDependencies ++= Seq(
  "com.hunorkovacs" % "koauth_2.11" % "1.0-SNAPSHOT"
)
```

## Step By Step Example - Consumer

How to build HTTP requests that should be OAuth signed, using this library.

todo write this readme part
