package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{EnhancedRequest, OauthRequest}
import com.hunorkovacs.koauth.service.OauthExtractor.{enhanceRequest, extractOauthParams, urlDecode}
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
      val request = OauthRequest(Method, UrlWithoutParams, HeaderWithSpace, UrlParams, BodyParams)
      extractOauthParams(request) must equalTo(OauthParamsList).await
    }
    "extract normal parameters sepatated by commas." in {
      val request = OauthRequest(Method, UrlWithoutParams, HeaderWithSpace.replaceAll(", ", ","), UrlParams, BodyParams)
      extractOauthParams(request) must equalTo(OauthParamsList).await
    }
    "extract empty values." in {
      val request = OauthRequest(Method, UrlWithoutParams, "OAuth oauth_token=\"\"", UrlParams, BodyParams)
      extractOauthParams(request) must equalTo(List(("oauth_token", ""))).await
    }
    "extract totally empty header" in {
      val request = OauthRequest(Method, UrlWithoutParams, "", UrlParams, BodyParams)
      extractOauthParams(request) must equalTo(List.empty[(String, String)]).await
    }
    "discard irregular words" in {
      val request = OauthRequest(Method, UrlWithoutParams, "Why is this here,oauth_token=\"123\",And this?", UrlParams, BodyParams)
      extractOauthParams(request) must equalTo(List(("oauth_token", "123"))).await
    }
  }

  "Enhancing requests" should {
    "enhance request with params" in {
      val request = OauthRequest(Method, UrlWithoutParams, HeaderWithSpace, UrlParams, BodyParams)
      enhanceRequest(request) must equalTo(
        EnhancedRequest(Method,
          UrlWithoutParams,
          UrlParams,
          BodyParams,
          OauthParamsList,
          OauthParamsList.toMap)).await
    }
  }
}
