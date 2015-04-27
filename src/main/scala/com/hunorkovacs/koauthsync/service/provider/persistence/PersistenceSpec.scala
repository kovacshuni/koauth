package com.hunorkovacs.koauthsync.service.provider.persistence

import com.hunorkovacs.koauthsync.service.DefaultTokenGenerator._
import org.specs2.mutable.Specification

import scala.concurrent.Await._
import scala.concurrent.duration._

abstract class PersistenceSpec(val pers: Persistence) extends Specification {

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

      pers.getRequestTokenSecret(consumerKey, requestToken) must beEqualTo(Some(requestTokenSecret)).await
    }
    "return None if the token has never been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val requestToken = generateTokenAndSecret._1

      pers.getRequestTokenSecret(consumerKey, requestToken) must beEqualTo(None).await
    }
    "return None if the token has existed before but was deleted since." in {
      val consumerKey = generateTokenAndSecret._1
      val (requestToken, requestTokenSecret) = generateTokenAndSecret
      val callback = "oob"

      ready(pers.persistRequestToken(consumerKey, requestToken, requestTokenSecret, callback), 1.0 second)
      ready(pers.deleteRequestToken(consumerKey, requestToken), 1.0 second)

      pers.getRequestTokenSecret(consumerKey, requestToken) must beEqualTo(None).await
    }
  }

  "Getting an Access Token Secret" should {
    "return it if the token has been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val (accessToken, accessTokenSecret) = generateTokenAndSecret
      val username = generateNonce

      ready(pers.persistAccessToken(consumerKey, accessToken, accessTokenSecret, username), 1.0 second)

      pers.getAccessTokenSecret(consumerKey, accessToken) must beEqualTo(Some(accessTokenSecret)).await
    }
    "return None if the token has never been persisted before." in {
      val consumerKey = generateTokenAndSecret._1
      val accessToken = generateTokenAndSecret._1

      pers.getAccessTokenSecret(consumerKey, accessToken) must beEqualTo(None).await
    }
  }

  "Getting who authorized a Request Token " should {
    "return None if the token has never been authorized." in {
      val consumerKey = generateTokenAndSecret._1
      val (requestToken, requestTokenSecret) = generateTokenAndSecret
      val verifier = generateVerifier
      val callback = "oob"

      ready(pers.persistRequestToken(consumerKey, requestToken, requestTokenSecret, callback), 1.0 seconds)

      pers.whoAuthorizedRequestToken(consumerKey, requestToken, verifier) must beEqualTo(None).await
    }
    "return None if the token does not exist." in {
      val consumerKey = generateTokenAndSecret._1
      val requestToken = generateTokenAndSecret._1
      val verifier = generateVerifier

      pers.whoAuthorizedRequestToken(consumerKey, requestToken, verifier) must beEqualTo(None).await
    }
  }

  "Getting the username for the Access Token" should {
    "return the username if the token exists." in {
      val consumerKey = generateTokenAndSecret._1
      val (accessToken, accessTokenSecret) = generateTokenAndSecret
      val username = generateNonce

      ready(pers.persistAccessToken(consumerKey, accessToken, accessTokenSecret, username), 1.0 second)

      pers.getUsername(consumerKey, accessToken) must beEqualTo(Some(username)).await
    }
    "return None if the token does not exist." in {
      val consumerKey = generateTokenAndSecret._1
      val accessToken = generateTokenAndSecret._1

      pers.getUsername(consumerKey, accessToken) must beEqualTo(None).await
    }
  }
}
