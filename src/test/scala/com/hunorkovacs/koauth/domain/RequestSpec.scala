package com.hunorkovacs.koauth.domain

import com.hunorkovacs.koauth.domain.KoauthRequest._
import com.hunorkovacs.koauth.domain.OauthParams.CallbackName
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

  "Extracing URL params" should {
    "extract normal parameters separated with &." in {
      extractUrlParams("a=1&b=2") must equalTo(List(("a", "1"), ("b", "2")))
    }
    "URL decode keys and values." in {
      extractUrlParams("the%20key=the%20value&b=2") must equalTo(List(("the key", "the value"), ("b", "2")))
    }
    "extract keys with no values as empty string values." in {
      extractUrlParams("a=1&b") must equalTo(List(("a", "1"), ("b", "")))
    }
    "extract multiple = occurences using the first =." in {
      extractUrlParams("a=1&b=1=2=3") must equalTo(List(("a", "1"), ("b", "1=2=3")))
    }
    "not support commas as list of values yet.." in {
      extractUrlParams("a=1&b=1,2,3") must equalTo(List(("a", "1"), ("b", "1,2,3")))
    }
  }

  "Creating a " + KoauthRequest.getClass.getSimpleName + " from only a URL" should {
    "decode url and body parameters." in {
      KoauthRequest("GET",
        "http://abc.com/the/path?a=b&the%20key=the%20value#nofragment=15",
        Some("alpha=beta&the%20body%20key=the%20body%20value")) must equalTo(

        KoauthRequest("GET",
          "http://abc.com/the/path",
          List(("a", "b"), ("the key", "the value")),
          List(("alpha", "beta"), ("the body key", "the body value")),
          List.empty))
    }
    "decode no parameters as empty." in {
      KoauthRequest("POST", "http://abc.com/the/path", None) must equalTo(
        KoauthRequest("POST", "http://abc.com/the/path", List.empty, List.empty, List.empty))
    }
    "decode Authorization header as well." in {
      KoauthRequest("GET",
        "http://abc.com/the/path?a=b&the%20key=the%20value#nofragment=15",
        Some("OAuth oauth_callback=\"http%3A%2F%2F127.0.0.1%3A8080%2FaccessToken\""),
        Some("alpha=beta&the%20body%20key=the%20body%20value")) must equalTo(

        KoauthRequest("GET",
          "http://abc.com/the/path",
          List(("a", "b"), ("the key", "the value")),
          List(("alpha", "beta"), ("the body key", "the body value")),
          List((CallbackName, "http://127.0.0.1:8080/accessToken"))))
    }
  }
}
