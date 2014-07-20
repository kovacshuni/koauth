package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.OauthParams.{tokenSecretName, consumerSecretName}
import com.hunorkovacs.koauth.domain.Request
import com.hunorkovacs.koauth.service.DefaultConsumerService._
import com.hunorkovacs.koauth.service.Arithmetics.urlEncode
import org.specs2.mutable.Specification

import scala.concurrent.Await
import scala.concurrent.duration._

class ConsumerServiceSpec extends Specification {

  val Method = "POST"
  val Url = "https://api.twitter.com/1/statuses/update.json"
  val UrlParams = List(("include_entities", "true"))
  val BodyParams = List(("status", "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"))
  val ConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val Token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val Timestamp = "1318622958"
  val Callback = "https://twitter.com/callback"
  val Username = "username123"
  val Password = "password!@#"
  val Verifier = "9f38h8hf83h22#$%@!"
  val OauthParamsList = List(("oauth_consumer_key", ConsumerKey),
    (consumerSecretName, ConsumerSecret),
    ("oauth_token", Token),
    ("oauth_token_secret", TokenSecret),
    ("oauth_timestamp", Timestamp),
    ("oauth_nonce", Nonce),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_version", "1.0"))
  val AuthHeader = "OAuth oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"" +
    ", oauth_nonce=\"" + urlEncode(Nonce) + "\"" +
    ", oauth_signature=\"" + urlEncode(Signature) + "\"" +
    ", oauth_signature_method=\"HMAC-SHA1\"" +
    ", oauth_timestamp=\"" + urlEncode(Timestamp) + "\"" +
    ", oauth_token=\"" + urlEncode(Token) + "\"" +
    ", oauth_version=\"1.0\""
  val SignatureBase = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"

  "Creating a 'Request Token' request" should {
    "include all the necessary OAuth parameters." in {
      val request = Request(Method, Url, "", List.empty, List.empty)

      val header = Await.result(createRequestTokenRequest(request, ConsumerKey, ConsumerSecret, Callback), 1.0 seconds)

      header must contain("oauth_callback=\"" + urlEncode(Callback) + "\"") and {
        header must contain("oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"")
      } and {
        header must contain(", oauth_nonce=\"")
      } and {
        header must contain(", oauth_signature=\"")
      } and {
        header must contain(", oauth_signature_method=\"HMAC-SHA1\"")
      } and {
        header must contain(", oauth_timestamp=\"")
      } and {
        header must contain(", oauth_version=\"1.0\"")
      }
    }
  }

  "Creating a 'Authorize' request" should {
    "include all the necessary OAuth parameters." in {
      val request = Request(Method, Url, "", List.empty, List.empty)

      val header = Await.result(createAuthorizeRequest(request, ConsumerKey, Token, Username, Password), 1.0 seconds)

      header must contain("oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"") and {
        header must contain("oauth_token=\"" + urlEncode(Token) + "\"")
      } and {
        header must contain("username=\"" + urlEncode(Username) + "\"")
      } and {
        header must contain("password=\"" + urlEncode(Password) + "\"")
      }
    }
  }

  "Creating a 'Access Token' request" should {
    "include all the necessary OAuth parameters." in {
      val request = Request(Method, Url, "", List.empty, List.empty)

      val header = Await.result(createAccessTokenRequest(request, ConsumerKey, ConsumerSecret, Token, TokenSecret, Verifier), 1.0 seconds)

      header must contain("oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"") and {
        header must contain("oauth_token=\"" + urlEncode(Token) + "\"")
      } and {
        header must contain("oauth_verifier=\"" + urlEncode(Verifier) + "\"")
      } and {
        header must contain(", oauth_nonce=\"")
      } and {
        header must contain(", oauth_signature=\"")
      } and {
        header must contain(", oauth_signature_method=\"HMAC-SHA1\"")
      } and {
        header must contain(", oauth_timestamp=\"")
      } and {
        header must contain(", oauth_version=\"1.0\"")
      }
    }
  }

  "Creating a 'Oauthenticate' request" should {
    "include all the necessary OAuth parameters." in {
      val request = Request(Method, Url, "", List.empty, List.empty)

      val header = Await.result(createOauthenticatedRequest(request, ConsumerKey, ConsumerSecret, Token, TokenSecret), 1.0 seconds)

      header must contain("oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"") and {
        header must contain("oauth_token=\"" + urlEncode(Token) + "\"")
      } and {
        header must contain(", oauth_nonce=\"")
      } and {
        header must contain(", oauth_signature=\"")
      } and {
        header must contain(", oauth_signature_method=\"HMAC-SHA1\"")
      } and {
        header must contain(", oauth_timestamp=\"")
      } and {
        header must contain(", oauth_version=\"1.0\"")
      }
    }
  }

  "Creating a general signed request" should {
    "sign correctly and include signature in Authorization header together with the rest of the parameters." in {
      val request = new Request(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)

      createGeneralSignedRequest(request) must beEqualTo(AuthHeader).await
    }
  }

  "Creating a signature base" should {
    "exclude secrets, encode, sort, concat correctly every parameter." in {
      val request = new Request(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)

      createSignatureBase(request) must beEqualTo(SignatureBase).await
    }
  }

  "Signing a request " should {
    "give the correct signature." in {
      val request = new Request(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)

      signRequest(request) must beEqualTo(Signature).await
    }
    "give the correct signature when no Token Secret is present." in {
      val params = OauthParamsList.filterNot(p => tokenSecretName == p._1)
      val request = new Request(Method, Url, UrlParams, BodyParams, params, params.toMap)

      signRequest(request) must beEqualTo("KaRibr4jurQUGNDvM5Kp+qd4AHw=").await
    }
  }

}
