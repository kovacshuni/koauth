package com.hunorkovacs.koauth.domain

import com.hunorkovacs.koauth.domain.KoauthRequest.extractOauthParams
import org.specs2.mutable.Specification

class RequestSpec extends Specification {

  val HeaderWithSpace = "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", oauth_version=\"1.0\""
  val OauthParamsList = List(("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog"),
    ("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"),
    ("oauth_signature", "tnnArxj06cWHq44gCs1OSKk/jLY="),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", "1318622958"),
    ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
    ("oauth_version", "1.0"))


  "Extracting OAuth params" should {
    "extract normal parameters separated with commas&spaces." in {
      extractOauthParams(Some(HeaderWithSpace)) must equalTo(OauthParamsList)
    }
    "extract normal parameters sepatated by commas." in {
      extractOauthParams(Some(HeaderWithSpace.replaceAll(", ", ","))) must equalTo(OauthParamsList)
    }
    "extract empty values." in {
      extractOauthParams(Some("OAuth oauth_token=\"\"")) must equalTo(List(("oauth_token", "")))
    }
    "extract totally empty header." in {
      extractOauthParams(Some("")) must equalTo(List.empty[(String, String)])
    }
    "extract not existing header." in {
      extractOauthParams(None) must equalTo(List.empty[(String, String)])
    }
    "discard irregular words." in {
      extractOauthParams(Some("Why is this here,oauth_token=\"123\",And this?")) must
      equalTo(List(("oauth_token", "123")))
    }
  }
}
