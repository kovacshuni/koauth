package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthCombiner.{concatItemsForSignature, normalizeOauthParamsForSignature, encodePairConcat, pairEncodeConcat, urlEncode}
import org.specs2.mutable._

class OauthCombinerSpec extends Specification {

  val NormalCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
  val IllegalCharacters = " !\"#$%&\'()*+,/:;<=>?@"
  val IllegalCharactersEncoded = "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3C%3D%3E%3F%40"
  val DoubleByteCharacters = "áéő"
  val DoubleByteCharactersEncoded = "%C3%A1%C3%A9%C5%91"
  val Method = "GET"
  val HeaderWithSpace = "OAuth oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\", oauth_nonce=\"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg\", oauth_signature=\"tnnArxj06cWHq44gCs1OSKk%2FjLY%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1318622958\", oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\", oauth_version=\"1.0\""
  val RequestParamsList = List(("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog"),
    ("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"),
    ("oauth_signature", "tnnArxj06cWHq44gCs1OSKk/jLY="),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", "1318622958"),
    ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
    ("oauth_version", "1.0"))
  val EncodedUrl = "http%3A%2F%2Fgithub.com%2Fkovacshuni%2Fkoauth"
  val ConcatenatedRequestParams = "oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature%3DtnnArxj06cWHq44gCs1OSKk%2FjLY%3D%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0"
  val NormalizedRequestParams = "oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0"
  val SignatureBase = s"$Method&$EncodedUrl&$NormalizedRequestParams"

  val ResponseParamsList = List(("oauth_token", "ab3cd9j4ks73hf7g"),
    ("oauth_token_secret", "xyz4992k83j47x0b"))
  val ResponseBody = "oauth_token=ab3cd9j4ks73hf7g&oauth_token_secret=xyz4992k83j47x0b"

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

  "Combining OAuth response params" should {
    "encode, pair keys with values by equals sign and concatenate params with ampersand" in {
      encodePairConcat(ResponseParamsList) must equalTo (ResponseBody).await
    }
  }

  "Combining OAuth request params, while normalizing for signature" should {
    "first pair keys with values by equals, encode, then concatenate with ampersand" in {
      pairEncodeConcat(RequestParamsList) must equalTo(ConcatenatedRequestParams).await
    }
  }

  "Normalizing request parameters for signature" should {
    "normalize params" in {
      normalizeOauthParamsForSignature(RequestParamsList) must equalTo (NormalizedRequestParams).await
    }
    "sort params" in {
      normalizeOauthParamsForSignature(List(("b", "3"), ("a", "2"), ("a", "1"))) must equalTo ("a%3D1%26a%3D2%26b%3D3").await
    }
    "exclude realm and signature" in {
      normalizeOauthParamsForSignature(List(("realm", "3"), ("oauth_signature", "2"))) must equalTo ("").await
    }
    "empty values' keys are written anyways" in {
      normalizeOauthParamsForSignature(List(("a", ""), ("b", "2"))) must equalTo ("a%3D%26b%3D2").await
    }
  }

  "Concatenating Items For Signature" should {
    "work with best intended input" in {
      val request = new EnhancedRequest(HeaderWithSpace, "http://github.com/kovacshuni/koauth", Method,
        RequestParamsList, RequestParamsList.toMap)
      concatItemsForSignature(request) must equalTo (SignatureBase).await
    }
    "use lowercase URL" in {
      val request = new EnhancedRequest(HeaderWithSpace, "HTTP://GitHub.com/KovacsHuni/KOAuth",
        Method, RequestParamsList, RequestParamsList.toMap)
      concatItemsForSignature(request) must equalTo (s"$Method&$EncodedUrl&$NormalizedRequestParams").await
    }
    "include specific port" in {
      val request = new EnhancedRequest(HeaderWithSpace, "http://github.com:9000/kovacshuni/koauth",
        Method, RequestParamsList, RequestParamsList.toMap)
      concatItemsForSignature(request) must
        equalTo(s"$Method&http%3A%2F%2Fgithub.com%3A9000%2Fkovacshuni%2Fkoauth&$NormalizedRequestParams").await
    }
  }
}
