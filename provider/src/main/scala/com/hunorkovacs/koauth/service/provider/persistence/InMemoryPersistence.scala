package com.hunorkovacs.koauth.service.provider.persistence

import scala.collection.mutable.ListBuffer
import scala.concurrent.{ExecutionContext, Future}

class ExampleMemoryPersistence(ec: ExecutionContext) extends InMemoryPersistence(ec) {

  override val consumers: ListBuffer[Consumer] = ListBuffer[Consumer](
    Consumer(
      consumerKey = "OmFjJKNqU4v791CWj6QKaBaiEep0WBxJ",
      consumerSecret = "wr1KLYYH6o5yKFfiyN9ysKkPXcIAim2S",
      ownerUsername = "admin"
    )
  )

  override val requestTokens: ListBuffer[RequestToken] = ListBuffer[RequestToken](
    RequestToken(
      consumerKey = "OmFjJKNqU4v791CWj6QKaBaiEep0WBxJ",
      requestToken = "nHmH9Qv6vPhZuvLVfofIXoKqpKA6BcSq",
      requestTokenSecret = "S6o9gbm6l6yyR3kcry9kzj40C6mhErmu",
      callback = "oob",
      verifierUsername = None,
      verifier = None
    ),
    RequestToken(
      consumerKey = "OmFjJKNqU4v791CWj6QKaBaiEep0WBxJ",
      requestToken = "DGnMlgdnCxc5ur3ZYX5t1BSjUOJUyqfZ",
      requestTokenSecret = "y6v2ZtztCLH9Yewoeb4NoIXRmWlb74xV",
      callback = "oob",
      verifierUsername = Some("admin"),
      verifier = Some("W8FMcCtnDZ1Gw1m4")
    )
  )

  override val accessTokens: ListBuffer[AccessToken] = ListBuffer[AccessToken](
    AccessToken(
      consumerKey = "OmFjJKNqU4v791CWj6QKaBaiEep0WBxJ",
      accessToken = "NDW4H8pFTthDV7kmSkdyYDmiBspabYEW",
      accessTokenSecret = "e3lqNSPq1hU6v7FFnq6p6die6pFIYJU0",
      username = "admin"
    )
  )
}

class InMemoryPersistence(ec: ExecutionContext) extends Persistence {

  implicit private val implicitEc: ExecutionContext = ec

  val consumers: ListBuffer[Consumer] = ListBuffer.empty[Consumer]
  val requestTokens: ListBuffer[RequestToken] = ListBuffer.empty[RequestToken]
  val accessTokens: ListBuffer[AccessToken] = ListBuffer.empty[AccessToken]
  val nonces: ListBuffer[Nonce] = ListBuffer.empty[Nonce]

  override def nonceExists(nonce: String, consumerKey: String, token: String): Future[Boolean] = {
    Future {
      nonces.exists(p => nonce == p.nonce && consumerKey == p.consumerKey && token == p.token)
    }
  }

  override def whoAuthorizedRequestToken(consumerKey: String, requestToken: String, verifier: String): Future[Option[String]] = {
    Future {
      requestTokens.find(
        p =>
          consumerKey == p.consumerKey
            && requestToken == p.requestToken
            && p.verifier.contains(verifier)
      ) match {
        case None => None
        case Some(foundRequestToken) => foundRequestToken.verifierUsername
      }
    }
  }

  override def getCallback(consumerKey: String, requestToken: String): Future[Option[String]] = {
    Future {
      requestTokens
        .find(
          p =>
            consumerKey == p.consumerKey
              && requestToken == p.requestToken
        )
        .map(_.callback)
    }
  }

  override def getAccessTokenSecret(consumerKey: String, accessToken: String): Future[Option[String]] = {
    Future {
      accessTokens
        .find(t => consumerKey == t.consumerKey && accessToken == t.accessToken)
        .map(t => t.accessTokenSecret)
    }
  }

  override def persistAccessToken(consumerKey: String, accessToken: String, accessTokenSecret: String, username: String): Future[Unit] = {
    Future {
      accessTokens += AccessToken(consumerKey, accessToken, accessTokenSecret, username)
      Unit
    }
  }

  override def persistRequestToken(
      consumerKey: String,
      requestToken: String,
      requestTokenSecret: String,
      callback: String
  ): Future[Unit] = {
    Future {
      requestTokens += RequestToken(consumerKey, requestToken, requestTokenSecret, callback, None, None)
      Unit
    }
  }

  override def getConsumerSecret(consumerKey: String): Future[Option[String]] = {
    Future {
      consumers
        .find(c => consumerKey == c.consumerKey)
        .map(c => c.consumerSecret)
    }
  }

  override def getUsername(consumerKey: String, accessToken: String): Future[Option[String]] = {
    Future {
      accessTokens
        .find(t => consumerKey == t.consumerKey && accessToken == t.accessToken)
        .map(_.username)
    }
  }

  override def getRequestTokenSecret(consumerKey: String, requestToken: String): Future[Option[String]] = {
    Future {
      requestTokens
        .find(t => consumerKey == t.consumerKey && requestToken == t.requestToken)
        .map(t => t.requestTokenSecret)
    }
  }

  override def persistNonce(nonce: String, consumerKey: String, token: String): Future[Unit] = {
    Future {
      nonces += Nonce(nonce, consumerKey, token)
      Unit
    }
  }

  override def deleteRequestToken(consumerKey: String, requestToken: String): Future[Unit] = {
    Future {
      val someToken = requestTokens.find(t => consumerKey == t.consumerKey && requestToken == t.requestToken).get
      requestTokens -= someToken
    }
  }
}
