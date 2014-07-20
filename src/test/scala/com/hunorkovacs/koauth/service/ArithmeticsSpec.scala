package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.{ResponseOk, Request}
import com.hunorkovacs.koauth.service.Arithmetics._
import org.specs2.mutable._

class ArithmeticsSpec extends Specification {

  val NormalCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
  val IllegalCharacters = " !\"#$%&\'()*+,/:;<=>?@"
  val IllegalCharactersEncoded = "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3C%3D%3E%3F%40"
  val DoubleByteCharacters = "áéő"
  val DoubleByteCharactersEncoded = "%C3%A1%C3%A9%C5%91"

  val Method = "POST"
  val UrlWithoutParams = "https://api.twitter.com/1/statuses/update.json"
  val UrlParams = List(("include_entities", "true"))
  val OauthParamsList = List(("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog"),
    ("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"),
    ("oauth_signature", "tnnArxj06cWHq44gCs1OSKk/jLY="),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", "1318622958"),
    ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
    ("oauth_version", "1.0"))
  val BodyParams = List(("status", "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"))

  val Token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val TokenSecret = "t4958tu459t8u45t98u45t9485ut"
  val Callback = "true"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val TokenSecret2 = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"

  val NormalizedRequestParams = "include_entities=true&" +
    "oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&" +
    "oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&" +
    "oauth_signature_method=HMAC-SHA1&" +
    "oauth_timestamp=1318622958&" +
    "oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&" +
    "oauth_version=1.0&" +
    "status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
  val SignatureBase = "POST&" +
    "https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&" +
    "include_entities%3Dtrue%26" +
    "oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26" +
    "oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26" +
    "oauth_signature_method%3DHMAC-SHA1%26" +
    "oauth_timestamp%3D1318622958%26" +
    "oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26" +
    "oauth_version%3D1.0%26" +
    "status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"

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

  "URL encoding" should {
    "convert normal characters." in {
      urlEncode(NormalCharacters) must equalTo (NormalCharacters)
    }
    "convert illegal characters." in {
      urlEncode(IllegalCharacters) must equalTo (IllegalCharactersEncoded)
    }
    "convert characters on two bytes." in {
      urlEncode(DoubleByteCharacters) must equalTo (DoubleByteCharactersEncoded)
    }
  }

  "Issues an unauthorized Request Token" should {
    "include token, token secret and confirm callback"  in {
      createRequestTokenResponse(Token, TokenSecret, Callback) must
        equalTo (ResponseOk(s"oauth_callback_confirmed=$Callback&oauth_token=$Token&oauth_token_secret=$TokenSecret"))
    }
  }

  "Encoding, pairing, sorting and concatenating" should {
    "encode, pair keys with values by equals sign and concatenate params with ampersand." in {
      encodePairSortConcat(List(("oauth_token", "ab3cd9j4ks73hf7g"),
          ("oauth_token_secret", "xyz4992k83j47x0b"))) must
        equalTo ("oauth_token=ab3cd9j4ks73hf7g&" +
          "oauth_token_secret=xyz4992k83j47x0b")
    }
    "sort by key then value." in {
      encodePairSortConcat(List(("c", "3"), ("c", "2"), ("b", "2"), ("a", "1"))) must
        equalTo ("a=1&b=2&c=2&c=3")
    }
  }

  "Normalizing request parameters" should {
    "contain OAuth parameters, parameters in the HTTP POST request body, HTTP GET parameters." in {
      normalizeRequestParams(UrlParams, OauthParamsList, BodyParams) must
        equalTo (NormalizedRequestParams)
    }
    "sort parameters." in {
      normalizeRequestParams(List(("a", "1")), List(("b", "3"), ("a", "2")), List.empty) must
        equalTo ("a=1&a=2&b=3")
    }
    "exclude realm and signature." in {
      normalizeRequestParams(List.empty, List(("realm", "3"), ("oauth_signature", "2")), List.empty) must
        equalTo ("")
    }
    "write keys with empty values anyways." in {
      normalizeRequestParams(List.empty, List(("a", ""), ("b", "2")), List.empty) must
        equalTo ("a=&b=2")
    }
  }

  "Concatenating Request Elements For Signature" should {
    "contian HTTP request method, request URL, and normalized request parameters separated by '&'." in {
      val request = new Request(Method,
        UrlWithoutParams,
        UrlParams,
        BodyParams,
        OauthParamsList,
        OauthParamsList.toMap)
      concatItemsForSignature(request) must equalTo (SignatureBase)
    }
    "use lowercase URL." in {
      val request = new Request(Method,
        "HTTpS://Api.Twitter.com/1/Statuses/Update.JSON",
        UrlParams,
        BodyParams,
        OauthParamsList,
        OauthParamsList.toMap)
      concatItemsForSignature(request) must equalTo (SignatureBase)
    }
    "include specific port." in {
      val request = new Request(Method,
        "HTTpS://Api.Twitter.com:9000/1/Statuses/Update.JSON",
        UrlParams,
        BodyParams,
        OauthParamsList,
        OauthParamsList.toMap)
      concatItemsForSignature(request) must
        equalTo(SignatureBase.replaceAll("api.twitter.com", "api.twitter.com%3A9000"))
    }
  }

  "Singing a signature base with two secrets" should {
    "give the correct signature." in {
      sign(SignatureBase, ConsumerSecret, TokenSecret2) must
        equalTo (Signature)
    }
  }
}
