package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{OauthResponseOk, OauthResponse, OauthRequest, EnhancedRequest}
import org.mockito.Mockito._
import org.specs2.mutable._

class OauthServiceSpec extends Specification {

  val Method = "POST"
  val Url = "https://api.twitter.com/1/statuses/update.json"
  val UrlParams = List(("include_entities", "true"))
  val BodyParams = List(("status", "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"))
  val AuthHeader = "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", " +
    "oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", " +
    "oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", " +
    "oauth_signature_method=\"HMAC-SHA1\", " +
    "oauth_timestamp=\"1318622958\", " +
    "oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", " +
    "oauth_version=\"1.0\""
  val Request = new OauthRequest(Method, Url, AuthHeader, UrlParams, BodyParams)


  "'Request Token' request should" should {
    "generate token, token secret, save them and return them in the response." in {
      implicit val pers = mock(classOf[OauthPersistence])
      OauthService.requestToken(Request) must
        beEqualTo(OauthResponseOk("")).await
    }
  }
}
