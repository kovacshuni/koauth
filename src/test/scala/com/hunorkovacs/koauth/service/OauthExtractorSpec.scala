package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.Request.extractOauthParams
import com.hunorkovacs.koauth.service.OauthExtractor.urlDecode
import org.specs2.mutable._

class OauthExtractorSpec extends Specification {

  val NormalCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
  val IllegalCharacters = " !\"#$%&\'()*+,/:;<=>?@"
  val IllegalCharactersEncoded = "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3C%3D%3E%3F%40"
  val DoubleByteCharacters = "áéő"
  val DoubleByteCharactersEncoded = "%C3%A1%C3%A9%C5%91"

  val Method = "GET"
  val UrlWithoutParams = "https://api.twitter.com/1/statuses/update.json"
  val HeaderWithSpace = "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", oauth_version=\"1.0\""
  val UrlParams = List(("include_entities", "true"))
  val BodyParams = List(("status", "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"))
  val OauthParamsList = List(("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog"),
    ("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"),
    ("oauth_signature", "tnnArxj06cWHq44gCs1OSKk/jLY="),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", "1318622958"),
    ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
    ("oauth_version", "1.0"))

  "URL decoding" should {
    "convert normal characters." in {
      urlDecode(NormalCharacters) must equalTo (NormalCharacters)
    }
    "convert illegal characters." in {
      urlDecode(IllegalCharactersEncoded) must equalTo (IllegalCharacters)
    }
    "convert characters on two bytes." in {
      urlDecode(DoubleByteCharactersEncoded) must equalTo (DoubleByteCharacters)
    }
  }

  "Extracting OAuth params" should {
    "extract normal parameters separated with commas&spaces." in {
      extractOauthParams(HeaderWithSpace) must equalTo(OauthParamsList)
    }
    "extract normal parameters sepatated by commas." in {
      extractOauthParams(HeaderWithSpace.replaceAll(", ", ",")) must equalTo(OauthParamsList)
    }
    "extract empty values." in {
      extractOauthParams("OAuth oauth_token=\"\"") must equalTo(List(("oauth_token", "")))
    }
    "extract totally empty header." in {
      extractOauthParams("") must equalTo(List.empty[(String, String)])
    }
    "discard irregular words." in {
      extractOauthParams("Why is this here,oauth_token=\"123\",And this?") must
        equalTo(List(("oauth_token", "123")))
    }
  }
}
