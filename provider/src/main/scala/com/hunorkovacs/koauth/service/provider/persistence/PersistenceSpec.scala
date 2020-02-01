package com.hunorkovacs.koauth.service.provider.persistence

import org.specs2.concurrent.ExecutionEnv
import org.specs2.mock.Mockito
import org.specs2.mutable.Specification
import org.specs2.specification.Scope

import com.hunorkovacs.koauth.service.DefaultTokenGenerator._

import scala.concurrent.Await._
import scala.concurrent.duration._

abstract class PersistenceSpec(val pers: Persistence)(implicit ee: ExecutionEnv) extends Specification
  with Mockito with Scope {

  "Querying if Nonce exists" should {
    "return true if it was persisted before." in {
      val (nonce, consumerKey, token) = (generateNonce, generateTokenAndSecret._1, generateTokenAndSecret._1)

      ready(pers.persistNonce(nonce, consumerKey, token), 1.0 second)

      pers.nonceExists(nonce, consumerKey, token) must beEqualTo(true).await
    }
    "return false if it was not persisted before." in {
      val (nonce, consumerKey, token) = (generateNonce, generateTokenAndSecret._1, generateTokenAndSecret._1)

      ready(pers.persistNonce(nonce, consumerKey, token), 1.0 second)

      pers.nonceExists(generateNonce, consumerKey, token) must beEqualTo(false).await
    }
  }

  "Getting a Request Token Secret" should {
    "return it if the token has been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val (requestToken, requestTokenSecret) = generateTokenAndSecret
      val callback = "oob"

      ready(pers.persistRequestToken(consumerKey, requestToken, requestTokenSecret, callback), 1.0 second)

      pers.getRequestTokenSecret(consumerKey, requestToken) must beSome(requestTokenSecret).await
    }
    "return None if the token has never been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val requestToken = generateTokenAndSecret._1

      pers.getRequestTokenSecret(consumerKey, requestToken) must beNone.await
    }
    "return None if the token has existed before but was deleted since." in {
      val consumerKey = generateTokenAndSecret._1
      val (requestToken, requestTokenSecret) = generateTokenAndSecret
      val callback = "oob"

      ready(pers.persistRequestToken(consumerKey, requestToken, requestTokenSecret, callback), 1.0 second)
      ready(pers.deleteRequestToken(consumerKey, requestToken), 1.0 second)

      pers.getRequestTokenSecret(consumerKey, requestToken) must beNone.await
    }
  }

  "Getting an Access Token Secret" should {
    "return it if the token has been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val (accessToken, accessTokenSecret) = generateTokenAndSecret
      val username = generateNonce

      ready(pers.persistAccessToken(consumerKey, accessToken, accessTokenSecret, username), 1.0 second)

      pers.getAccessTokenSecret(consumerKey, accessToken) must beSome(accessTokenSecret).await
    }
    "return None if the token has never been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val accessToken = generateTokenAndSecret._1

      pers.getAccessTokenSecret(consumerKey, accessToken) must beNone.await
    }
  }

  "Getting who authorized a Request Token " should {
    "return None if the token has never been authorized." in {
      val consumerKey = generateTokenAndSecret._1
      val (requestToken, requestTokenSecret) = generateTokenAndSecret
      val verifier = generateVerifier
      val callback = "oob"

      ready(pers.persistRequestToken(consumerKey, requestToken, requestTokenSecret, callback), 1.0 seconds)

      pers.whoAuthorizedRequestToken(consumerKey, requestToken, verifier) must beNone.await
    }
    "return None if the token does not exist." in {
      val consumerKey = generateTokenAndSecret._1
      val requestToken = generateTokenAndSecret._1
      val verifier = generateVerifier

      pers.whoAuthorizedRequestToken(consumerKey, requestToken, verifier) must beNone.await
    }
  }

  "Getting the callback" should {
    "return the callback if the token exists." in {
      val consumerKey = generateTokenAndSecret._1
      val (requestToken, requestTokenSecret) = generateTokenAndSecret
      val callback = "http://www.example.com:5678/callback"

      ready(pers.persistRequestToken(consumerKey, requestToken, requestTokenSecret, callback), 1.0 seconds)

      pers.getCallback(consumerKey, requestToken) must beSome(callback).await
    }
    "return None if the token does not exist." in {
      pers.getCallback("ck", "rt") must beNone.await
    }
  }

  "Getting the username for the Access Token" should {
    "return the username if the token exists." in {
      val consumerKey = generateTokenAndSecret._1
      val (accessToken, accessTokenSecret) = generateTokenAndSecret
      val username = generateNonce

      ready(pers.persistAccessToken(consumerKey, accessToken, accessTokenSecret, username), 1.0 second)

      pers.getUsername(consumerKey, accessToken) must beSome(username).await
    }
    "return None if the token does not exist." in {
      val consumerKey = generateTokenAndSecret._1
      val accessToken = generateTokenAndSecret._1

      pers.getUsername(consumerKey, accessToken) must beNone.await
    }
  }
}
