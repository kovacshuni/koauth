package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics.urlEncode
import com.hunorkovacs.koauth.service.provider.DefaultVerifier._
import org.mockito.Matchers
import org.specs2.mock._
import org.specs2.mutable.{Before, Specification}

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
    "generate token, token secret, save them and return them in the response." in new commonMocks {
      val encodedCallback = urlEncode(Callback)
      val header = AuthHeader + ", oauth_callback=\"" + encodedCallback + "\""
      val request = Request("", "", header, List.empty, List.empty)
      var encodedToken, encodedSecret = ""
      pers.persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) answers { (p, m) =>
        p match {
          case a: Array[Object] =>
            a(1) match { case s: String => encodedToken = urlEncode(s) }
            a(2) match { case s: String => encodedSecret = urlEncode(s) }
        }
        successful(Unit)
      }
      verifier.verifyForRequestToken(request) returns successful(VerificationOk)

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was one(pers).persistRequestToken(Matchers.eq(ConsumerKey), anyString, anyString,
        Matchers.eq(Callback))(any[ExecutionContext]) and {
        response must beEqualTo(ResponseOk(s"oauth_callback_confirmed=$encodedCallback&" +
          s"oauth_token=$encodedToken&" +
          s"oauth_token_secret=$encodedSecret"))
      }
    }
    "return Unauthorized and should not touch persistence, if request items' verification is negative." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForRequestToken(request) returns successful(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(ResponseUnauthorized(MessageInvalidSignature))
      }
    }
    "return Bad Request and should not touch persistence, if request items' verification is unsupported." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForRequestToken(request) returns successful(VerificationUnsupported(MessageUnsupportedMethod))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(ResponseBadRequest(MessageUnsupportedMethod))
      }
    }
    "return Bad Request and should not touch persistence, if OAuth parameters are missing or duplicated." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForRequestToken(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(ResponseBadRequest(MessageParameterMissing))
      }
    }
  }

  "'Access Token' request" should {
    "generate token, token secret, save them and return them in the response if all ok." in new commonMocks {
      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", oauth_verifier=\"" + urlEncode(Verifier) + "\""
      val request = Request("", "", header, List.empty, List.empty)
      verifier.verifyForAccessToken(request) returns successful(VerificationOk)
      pers.whoAuthorizedRequesToken(Matchers.eq(ConsumerKey), Matchers.eq(RequestToken),
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

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was one(pers).whoAuthorizedRequesToken(ConsumerKey, RequestToken, Verifier) and {
        there was one(pers).persistAccessToken(ConsumerKey, accessToken, secret, Username)
      } and {
        response must beEqualTo(ResponseOk("oauth_token=" + urlEncode(accessToken) + "&" +
          "oauth_token_secret=" + urlEncode(secret)))
      }
    }

    "return Unauthorized and should not give Access Token, if Request Token was not authorized." in new commonMocks {
      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", oauth_verifier=\"" + urlEncode(Verifier) + "\""
      val request = Request("", "", header, List.empty, List.empty)
      verifier.verifyForAccessToken(request) returns successful(VerificationOk)
      pers.whoAuthorizedRequesToken(ConsumerKey, RequestToken, Verifier) returns successful(None)

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was one(pers).whoAuthorizedRequesToken(ConsumerKey, RequestToken, Verifier) and {
        there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseUnauthorized(MessageNotAuthorized))
      }
    }

    "return Unauthorized and should not touch persistence, if request items' verification is negative." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForAccessToken(request) returns successful(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).whoAuthorizedRequesToken(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseUnauthorized(MessageInvalidSignature))
      }
    }

    "return Bad Request and should not touch persistence, if request items' verification is unsupported." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForAccessToken(request) returns successful(VerificationUnsupported(MessageUnsupportedMethod))

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and
        (response must beEqualTo(ResponseBadRequest(MessageUnsupportedMethod)))
    }

    "return Bad Request and should not touch persistence, if OAuth parameters are missing or duplicated." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForAccessToken(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.accessToken(request), 1.0 seconds)

      there was no(pers).persistAccessToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        there was no(pers).whoAuthorizedRequesToken(anyString, anyString, anyString)(any[ExecutionContext])
      } and {
        response must beEqualTo(ResponseBadRequest(MessageParameterMissing))
      }
    }
  }

  "'Authorize Token' request" should {
    "authorize token by generating verifier for user." in new commonMocks {
      val header = "OAuth oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"" +
        ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", username=\"" + urlEncode(Username) + "\"" +
        ", password=\"" + urlEncode(Password) + "\""
      val request = Request("", "", header, List.empty, List.empty)
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

      val response = Await.result(service.authorize(request), 1.0 seconds)

      there was one(pers).authorizeRequestToken(ConsumerKey, RequestToken, Username, verifierKey) and {
        response must beEqualTo(ResponseOk("oauth_token=" + urlEncode(RequestToken) + "&" +
          "oauth_verifier=" + urlEncode(verifierKey)))
      }
    }
    "return Unauthorized and should not authorize token if credentials are invalid." in new commonMocks {
      val header = "OAuth oauth_consumer_key=\"" + urlEncode(ConsumerKey) + "\"" +
        ", oauth_token=\"" + urlEncode(RequestToken) + "\"" +
        ", username=\"" + urlEncode(Username) + "\"" +
        ", password=\"" + urlEncode(Password) + "\""
      val request = Request("", "", header, List.empty, List.empty)
      verifier.verifyForAuthorize(request) returns successful(VerificationFailed(MessageInvalidCredentials))

      val response = Await.result(service.authorize(request), 1.0 seconds)

      there was no(pers).authorizeRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(ResponseUnauthorized(MessageInvalidCredentials))
      }
    }
    "return Bad Request and should not authorize, if OAuth parameters are missing or duplicated." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForAuthorize(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.authorize(request), 1.0 seconds)

      there was no(pers).authorizeRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(ResponseBadRequest(MessageParameterMissing))
      }
    }
  }

  "'Accessing Protected Resources' request" should {
    "authenticate by by Consumer Secret and Access Token, return corresponding user." in new commonMocks {
      val header = AuthHeader + ", oauth_token=\"" + urlEncode(RequestToken) + "\""
      val request = Request("", "", header, List.empty, List.empty)
      verifier.verifyForOauthenticate(request) returns successful(VerificationOk)
      pers.getUsername(ConsumerKey, RequestToken) returns successful(Username)

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      response must beEqualTo(Right(Username))
    }
    "return Unauthorized if signature and other parameters are ok, but token is not a valid access token." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForOauthenticate(request) returns successful(VerificationFailed(MessageInvalidToken))

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).getUsername(anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(Left(ResponseUnauthorized(MessageInvalidToken)))
      }
    }
    "return Unauthorized if invalid signature." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForOauthenticate(request) returns successful(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).getUsername(anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(Left(ResponseUnauthorized(MessageInvalidSignature)))
      }
    }
    "return Bad Request and should not authenticate, if OAuth parameters are missing or duplicated." in new commonMocks {
      val request = emptyRequest
      verifier.verifyForOauthenticate(request) returns successful(VerificationUnsupported(MessageParameterMissing))

      val response = Await.result(service.oauthenticate(request), 1.0 seconds)

      there was no(pers).getUsername(anyString, anyString)(any[ExecutionContext]) and {
        response must beEqualTo(Left(ResponseBadRequest(MessageParameterMissing)))
      }
    }
  }

  private def emptyRequest = Request("", "", "", List.empty, List.empty)

  private trait commonMocks extends Before with Mockito {
    implicit lazy val pers = mock[Persistence]
    lazy val verifier = mock[Verifier]
    lazy val service = ProviderServiceFactory.createCustomOauthService(verifier)

    override def before = Nil
  }
}