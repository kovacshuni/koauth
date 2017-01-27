package com.hunorkovacs.koauth.service.consumer.synch

import com.hunorkovacs.koauth.domain.KoauthRequest
import com.hunorkovacs.koauth.domain.OauthParams.ConsumerSecretName
import com.hunorkovacs.koauth.service.Arithmetics.urlEncode
import org.specs2.mutable.Specification

class ConsumerServiceSpec extends Specification {

  val Method = "POST"
  val Url = "https://api.twitter.com/1/statuses/update.json"
  val UrlParams = List(("include_entities", "true"))
  val BodyParams = List(("status", "Hello Ladies + Gentlemen, a signed OAuth request!"))
  val ConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val Token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val Timestamp = "1318622958"
  val Callback = "https://twitter.com/callback"
  val Verifier = "9f38h8hf83h22#$%@!"
  val OauthParamsList = List(("oauth_consumer_key", ConsumerKey),
    (ConsumerSecretName, ConsumerSecret),
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

  import ConsumerService._

  "Creating a 'Request Token' request" should {
    "include all the necessary OAuth parameters." in {
      val request = KoauthRequest(Method, Url, None, List.empty, List.empty)

      val requestAndInfo = createRequestTokenRequest(request, ConsumerKey, ConsumerSecret, Callback)
      val header = requestAndInfo.header

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

  "Creating a 'Access Token' request" should {
    "include all the necessary OAuth parameters." in {
      val request = KoauthRequest(Method, Url, None, List.empty, List.empty)

      val requestAndInfo = createAccessTokenRequest(request, ConsumerKey, ConsumerSecret, Token, TokenSecret, Verifier)
      val header = requestAndInfo.header

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
      val request = KoauthRequest(Method, Url, None, List.empty, List.empty)

      val requestAndInfo = createOauthenticatedRequest(request, ConsumerKey, ConsumerSecret, Token, TokenSecret)
      val header = requestAndInfo.header

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
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)

      val requestAndInfo = createGeneralSignedRequest(request)
      val header = requestAndInfo.header

      header must beEqualTo(AuthHeader)
    }
  }

  "Creating a signature base" should {
    "exclude secrets, encode, sort, concat correctly every parameter." in {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)

      createSignatureBase(request) must beEqualTo(SignatureBase)
    }
  }
}
