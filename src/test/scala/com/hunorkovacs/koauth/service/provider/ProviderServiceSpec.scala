package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics.urlEncode
import com.hunorkovacs.koauth.service.provider.DefaultVerifier._
import com.hunorkovacs.koauth.service.provider.persistence.Persistence
import org.mockito.Matchers
import org.specs2.mock._
import org.specs2.mutable.{Before, Specification}
import org.specs2.specification.Scope

import scala.concurrent.Future.successful
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext}

class ProviderServiceSpec extends Specification with Mockito {

  val ConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val AuthHeader = "OAuth oauth_consumer_key=\"" + ConsumerKey + "\", " +
    "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", " +
    "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", " +
    "oauth_signature_method=\"HMAC-SHA1\", " +
    "oauth_timestamp=\"1318622958\", " +
    "oauth_version=\"1.0\""
  val Callback = "https://twitter.com/callback"
  val RequestToken = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val Verifier = "hfdp7dh39dks9884"
  val Username = "username123"
  val Password = "password!@#"

  "'Request Token' request" should {
    "generate token, token secret, save them and return them in the response." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val encodedCallback = urlEncode(Callback)
      val header = AuthHeader + ", oauth_callback=\"" + encodedCallback + "\""
      val request = KoauthRequest("", "", header, List.empty, List.empty)
      var token, secret = ""
      pers.persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) answers { (p, m) =>
        p match {
          case a: Array[Object] =>
            a(1) match { case s: String => token = s }
            a(2) match { case s: String => secret = urlEncode(s) }
        }
        successful(Unit)
      }
      pers.persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(""))(any[ExecutionContext]) returns successful(Unit)
      verifier.verifyForRequestToken(request) returns successful(VerificationOk)

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was one(pers).persistRequestToken(ConsumerKey, token, secret, Callback) and {
        there was one(pers).persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(""))(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseOk(s"oauth_callback_confirmed=$encodedCallback" +
          "&oauth_token=" + urlEncode(token) +
          "&oauth_token_secret=" + urlEncode(secret)))
      }
    }
    "return Unauthorized and should not touch persistence, if request items' verification is negative." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForRequestToken(request) returns successful(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseUnauthorized(MessageInvalidSignature))
      }
    }
    "return Bad Request and should not touch persistence, if request items' verification is unsupported." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForRequestToken(request) returns successful(VerificationUnsupported(MessageUnsupportedMethod))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseBadRequest(MessageUnsupportedMethod))
      }
    }
    "return Bad Request and should not touch persistence, if OAuth parameters are missing or duplicated." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForRequestToken(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseBadRequest(MessageParameterMissing))
      }
    }
  }

  "'Access Token' request" should {
    "generate token, token secret, save them and return them in the response if all ok." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", oauth_verifier=\"" + urlEncode(Verifier) + "\""
      val request = KoauthRequest("", "", header, List.empty, List.empty)
      verifier.verifyForAccessToken(request) returns successful(VerificationOk)
      pers.whoAuthorizedRequestToken(Matchers.eq(ConsumerKey), Matchers.eq(RequestToken),
        Matchers.eq(Verifier))(any[ExecutionContext]) returns successful(Some(Username))
      var accessToken, secret = ""
      pers.persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) answers { (p, m) =>
        p match {
          case a: Array[Object] =>
            a(1) match { case s: String => accessToken = s }
            a(2) match { case s: String => secret = s }
        }
        successful(Unit)
      }
      pers.persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext]) returns successful(Unit)

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was one(pers).whoAuthorizedRequestToken(ConsumerKey, RequestToken, Verifier) and {
        there was one(pers).persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext])
      } and {
        there was one(pers).persistAccessToken(ConsumerKey, accessToken, secret, Username)
      } and {
        response must beEqualTo(ResponseOk("oauth_token=" + urlEncode(accessToken) + "&" +
          "oauth_token_secret=" + urlEncode(secret)))
      }
    }

    "return Unauthorized and should not give Access Token, if Request Token was not authorized." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", oauth_verifier=\"" + urlEncode(Verifier) + "\""
      val request = KoauthRequest("", "", header, List.empty, List.empty)
      verifier.verifyForAccessToken(request) returns successful(VerificationOk)
      pers.whoAuthorizedRequestToken(ConsumerKey, RequestToken, Verifier) returns successful(None)

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was one(pers).whoAuthorizedRequestToken(ConsumerKey, RequestToken, Verifier) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseUnauthorized(MessageNotAuthorized))
      }
    }

    "return Unauthorized and should not touch persistence, if request items' verification is negative." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForAccessToken(request) returns successful(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        there was no(pers).whoAuthorizedRequestToken(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseUnauthorized(MessageInvalidSignature))
      }
    }

    "return Bad Request and should not touch persistence, if request items' verification is unsupported." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForAccessToken(request) returns successful(VerificationUnsupported(MessageUnsupportedMethod))

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseBadRequest(MessageUnsupportedMethod))
      }
    }

    "return Bad Request and should not touch persistence, if OAuth parameters are missing or duplicated." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForAccessToken(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        there was no(pers).whoAuthorizedRequestToken(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseBadRequest(MessageParameterMissing))
      }
    }
  }

  "'Authorize Token' request" should {
    "authorize token by generating verifier for user." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val header = AuthHeader +
        ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", username=\"" + urlEncode(Username) + "\"" +
        ", password=\"" + urlEncode(Password) + "\""
      val request = KoauthRequest("", "", header, List.empty, List.empty)
      verifier.verifyForAuthorize(request) returns successful(VerificationOk)
      var verifierKey = ""
      pers.authorizeRequestToken(Matchers.eq(ConsumerKey), Matchers.eq(RequestToken),
        Matchers.eq(Username), anyString)(any[ExecutionContext]) answers { (p, m) =>
        p match {
          case a: Array[Object] =>
            a(3) match { case s: String => verifierKey = s }
        }
        successful(Unit)
      }
      pers.persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext]) returns successful(Unit)

      val response = Await.result(service.authorize(request), 1.0 seconds)

      there was one(pers).authorizeRequestToken(ConsumerKey, RequestToken, Username, verifierKey) and {
        there was one(pers).persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseOk("oauth_token=" + urlEncode(RequestToken) + "&" +
          "oauth_verifier=" + urlEncode(verifierKey)))
      }
    }
    "return Unauthorized and should not authorize if verification returns unauthorized." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForAuthorize(request) returns successful(VerificationFailed(MessageInvalidCredentials))

      val response = Await.result(service.authorize(request), 1.0 seconds)

      there was no(pers).authorizeRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseUnauthorized(MessageInvalidCredentials))
      }
    }
    "return Bad Request and should not authorize, if verification returns unsupported." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForAuthorize(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.authorize(request), 1.0 seconds)

      there was no(pers).authorizeRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseBadRequest(MessageParameterMissing))
      }
    }
  }

  "'Accessing Protected Resources' request" should {
    "authenticate by by Consumer Secret and Access Token, return corresponding user." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\""
      val request = KoauthRequest("", "", header, List.empty, List.empty)
      verifier.verifyForOauthenticate(request) returns successful(VerificationOk)
      pers.getUsername(ConsumerKey, RequestToken) returns successful(Some(Username))
      pers.persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext]) returns successful(Unit)

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      response must beEqualTo(Right(Username)) and {
        there was one(pers).persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext])
      }
    }
    "return Unauthorized if signature and other parameters are ok, but token is not a valid access token." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForOauthenticate(request) returns successful(VerificationFailed(MessageInvalidToken))

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).getUsername(anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(Left(ResponseUnauthorized(MessageInvalidToken)))
      }
    }
    "return Unauthorized if signature and other parameters are ok, but user does not exit for Consumer Key and Access Token." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\""
      val request = KoauthRequest("", "", header, List.empty, List.empty)
      verifier.verifyForOauthenticate(request) returns successful(VerificationOk)
      pers.getUsername(ConsumerKey, RequestToken) returns successful(None)
      pers.persistNonce(anyString, Matchers.eq(ConsumerKey), Matchers.eq(RequestToken))(any[ExecutionContext]) returns successful(Unit)

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(Left(ResponseUnauthorized(MessageUserInexistent)))
      }
    }
    "return Unauthorized if invalid signature." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForOauthenticate(request) returns successful(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).getUsername(anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(Left(ResponseUnauthorized(MessageInvalidSignature)))
      }
    }
    "return Bad Request and should not authenticate, if OAuth parameters are missing or duplicated." in {
      implicit lazy val pers = mock[Persistence]
      lazy val verifier = mock[Verifier]
      lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

      val request = emptyRequest
      verifier.verifyForOauthenticate(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).getUsername(anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).persistNonce(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(Left(ResponseBadRequest(MessageParameterMissing)))
      }
    }
  }

  private def emptyRequest = KoauthRequest("", "", "", List.empty, List.empty)
}
