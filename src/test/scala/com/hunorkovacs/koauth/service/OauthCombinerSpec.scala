package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthCombiner.{concatItemsForSignature, normalizeOauthParamsForSignature, encodePairConcat, urlEncode}
import com.hunorkovacs.koauth.service.OauthExtractorSpec._
import org.specs2.mutable._

class OauthCombinerSpec extends Specification {

  val ResponseParamsList = List(("oauth_token", "ab3cd9j4ks73hf7g"),
    ("oauth_token_secret", "xyz4992k83j47x0b"))
  val ResponseBody = "oauth_token=ab3cd9j4ks73hf7g&oauth_token_secret=xyz4992k83j47x0b"
  val NormalizedRequestParams = "oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0"
  val EncodedUrl = "http%3A%2F%2Fgithub.com%2Fkovacshuni%2Fkoauth"

  "URL encoding" should {
    "convert normal characters" in {
      urlEncode(NormalCharacters) must equalTo (NormalCharacters)
    }
    "convert illegal characters" in {
      urlEncode(IllegalCharacters) must equalTo (IllegalCharactersEncoded)
    }
    "convert characters on two bytes" in {
      urlEncode(DoubleByteCharacters) must equalTo (DoubleByteCharactersEncoded)
    }
  }

  "Combining OAuth params" should {
    "encode, pair keys with values by equals sign and concatenate params with ampersand" in {
      encodePairConcat(ResponseParamsList) must equalTo (ResponseBody).await
    }
  }

  "Normalizing request parameters for signature" should {
    "normalize params" in {
      normalizeOauthParamsForSignature(RequestParamsList) must equalTo (NormalizedRequestParams).await
    }
    "sort params" in {
      normalizeOauthParamsForSignature(List(("b", "3"), ("a", "2"), ("a", "1"))) must equalTo ("a=1&a=2&b=3").await
    }
    "exclude realm and signature" in {
      normalizeOauthParamsForSignature(List(("realm", "3"), ("oauth_signature", "2"))) must equalTo ("").await
    }
    "empty values' keys are written anyways" in {
      normalizeOauthParamsForSignature(List(("a", ""), ("b", "2"))) must equalTo ("a=&b=2").await
    }
  }

  "Concatenating Items For Signature" should {
    "work with best intended input" in {
      val request = new EnhancedRequest(HeaderWithSpace, Url, Method, RequestParamsList, RequestParamsList.toMap)
      concatItemsForSignature(request) must equalTo (s"$Method&$EncodedUrl&$NormalizedRequestParams").await
    }
    "use lowercase URL" in {
      val request = new EnhancedRequest(HeaderWithSpace, "HTTP://GitHub.com/KovacsHuni/KOAuth",
        Method, RequestParamsList, RequestParamsList.toMap)
      concatItemsForSignature(request) must equalTo (s"$Method&$EncodedUrl&$NormalizedRequestParams").await
    }
    "include specific port" in {
      val request = new EnhancedRequest(HeaderWithSpace, "http://github.com:9000/kovacshuni/koauth",
        Method, RequestParamsList, RequestParamsList.toMap)
      concatItemsForSignature(request).must(
        equalTo(s"$Method&http%3A%2F%2Fgithub.com%3A9000%2Fkovacshuni%2Fkoauth&$NormalizedRequestParams").await)
    }
  }
}
