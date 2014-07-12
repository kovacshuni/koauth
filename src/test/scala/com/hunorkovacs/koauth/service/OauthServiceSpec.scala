package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{OauthResponseOk, OauthRequest}
import com.hunorkovacs.koauth.service.OauthCombiner.urlEncode
import com.hunorkovacs.koauth.service.OauthExtractor.enhanceRequest
import org.mockito.Matchers
import org.specs2.mutable._
import org.specs2.mock._

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
    "generate token, token secret, save them and return them in the response." in {
      val encodedCallback = urlEncode(Callback)
      val header = AuthHeader + ", oauth_callback=\"" + encodedCallback + "\""
      val request = new OauthRequest("", "", header, List.empty, List.empty)
      val enhanced = Await.result(enhanceRequest(request), 1.0 seconds)
      implicit val pers = mock[OauthPersistence]
      var encodedToken, encodedSecret = ""
      pers.persistRequestToken(anyString, anyString, anyString, anyString)(any[ExecutionContext]) answers { (p, m) =>
        p match {
          case a: Array[Object] =>
            a(1) match { case s: String => encodedToken = urlEncode(s) }
            a(2) match { case s: String => encodedSecret = urlEncode(s) }
        }
        Future(Unit)
      }
      val verifier = mock[OauthVerifier]
      verifier.verifyForRequestToken(enhanced) returns Future(VerificationOk)
      val service = OauthServiceFactory.createCustomOauthService(verifier)

      val response = Await.result(service.requestToken(request), 1.0 seconds)

      there was one(pers).persistRequestToken(Matchers.eq(ConsumerKey), anyString, anyString,
        Matchers.eq(Callback))(any[ExecutionContext])
      response must beEqualTo (OauthResponseOk(s"oauth_callback_confirmed=$encodedCallback&" +
        s"oauth_token=$encodedToken&" +
        s"oauth_token_secret=$encodedSecret"))
    }
  }
}
