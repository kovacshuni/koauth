package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.DefaultOauthVerifier.{MessageUnsupportedMethod, MessageInvalidSignature}
import com.hunorkovacs.koauth.service.OauthCombiner.urlEncode
import com.hunorkovacs.koauth.service.OauthExtractor.enhanceRequest
import org.mockito.Matchers
import org.specs2.mock._
import org.specs2.mutable.{Before, Specification}

import scala.concurrent.{ExecutionContext, Await, Future}
import scala.concurrent.duration._

class OauthServiceSpec extends Specification with Mockito {

  val ConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val AuthHeader = "OAuth oauth_consumer_key=\"" + ConsumerKey + "\", " +
    "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", " +
    "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", " +
    "oauth_signature_method=\"HMAC-SHA1\", " +
    "oauth_timestamp=\"1318622958\", " +
    "oauth_version=\"1.0\""
  val Callback = "https://twitter.com/callback"

  "'Request Token' request should" should {
    "generate token, token secret, save them and return them in the response." in new commonMocks {
      val encodedCallback = urlEncode(Callback)
      val header = AuthHeader + ", oauth_callback=\"" + encodedCallback + "\""
      val request = new OauthRequest("", "", header, List.empty, List.empty)
      val enhanced = Await.result(enhanceRequest(request), 1.0 seconds)
      var encodedToken, encodedSecret = ""
      pers.persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) answers { (p, m) =>
        p match {
          case a: Array[Object] =>
            a(1) match { case s: String => encodedToken = urlEncode(s) }
            a(2) match { case s: String => encodedSecret = urlEncode(s) }
        }
        Future(Unit)
      }
      verifier.verifyForRequestToken(enhanced) returns Future(VerificationOk)

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was one(pers).persistRequestToken(Matchers.eq(ConsumerKey), anyString, anyString,
        Matchers.eq(Callback))(any[ExecutionContext])
      response must beEqualTo (OauthResponseOk(s"oauth_callback_confirmed=$encodedCallback&" +
        s"oauth_token=$encodedToken&" +
        s"oauth_token_secret=$encodedSecret"))
    }
    "return Unauthorized and should not touch persistence, if request items' verification is negative." in new commonMocks {
      val request = new OauthRequest("", "", "", List.empty, List.empty)
      val enhanced = new EnhancedRequest("", "", List.empty, List.empty, List.empty, Map.empty)
      verifier.verifyForRequestToken(enhanced) returns Future(VerificationFailed(MessageInvalidSignature))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext])
      response must beEqualTo (OauthResponseUnauthorized(MessageInvalidSignature))
    }
    "return Bad Request and should not touch persistence, if request items' verification is unsupported." in new commonMocks {
      val request = new OauthRequest("", "", "", List.empty, List.empty)
      val enhanced = new EnhancedRequest("", "", List.empty, List.empty, List.empty, Map.empty)
      verifier.verifyForRequestToken(enhanced) returns Future(VerificationUnsupported(MessageUnsupportedMethod))

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was no(pers).persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext])
      response must beEqualTo (OauthResponseBadRequest(MessageUnsupportedMethod))
    }
    "return Bad Request and should not touch persistence, if OAuth parameters are missing or duplicated." in new commonMocks {

    }
  }

  private trait commonMocks extends Before with Mockito {
    implicit lazy val pers = mock[OauthPersistence]
    lazy val verifier = mock[OauthVerifier]
    lazy val service = OauthServiceFactory.createCustomOauthService(verifier)

    override def before = Nil
  }
}
