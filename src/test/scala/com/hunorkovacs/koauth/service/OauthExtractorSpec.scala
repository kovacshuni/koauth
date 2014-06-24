package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.service.OauthExtractor.urlDecode
import com.hunorkovacs.koauth.service.OauthExtractorSpec._
import org.specs2.mutable._

class OauthExtractorSpec extends Specification {

  "URL decoding" should {
    "convert normal characters" in {
      urlDecode(NormalCharacters) must equalTo (NormalCharacters)
    }
    "convert illegal characters" in {
      urlDecode(IllegalCharactersEncoded) must equalTo (IllegalCharacters)
    }
    "convert characters on two bytes" in {
      urlDecode(DoubleByteCharactersEncoded) must equalTo (DoubleByteCharacters)
    }
  }

//   private final val SampleHeader = "OAuth realm=\"http://localhost:9000/authorization/request-token\"," +
//     "oauth_consumer_key=\"something%20space\",oauth_signature_method=\"HMAC-SHA1\",oauth_timestamp=\"1402347948\"," +
//     "oauth_nonce=\"hly1EI\",oauth_version=\"1.0\",oauth_signature=\"aGFG3tBdf5qwqMJgDkoQ0pvo7Mc%3D\""
//
//   "Extracting OAuth Parameters" should {
//     "extract simple" in {
//       OauthExtractor.extractAllOauthParams("OAuth keyA=\"valA\",keyB=\"valB\"") must
//         beEqualTo(Array[String]("keyA=valA", "keyB=valB"))
//     }
//     "URL unescape" in {
//       OauthExtractor.extractAllOauthParams("OAuth key%20A=\"val%20A\",keyB=\"%C3%9A\"") must
//         beEqualTo(Array[String]("key A=val A", "keyB=Ú"))
//     }
//   }
//
//  "Combining OAuth Response Parameters" should {
//    "combine simple" in {
//      OauthExtractor.combineOauthParams(Array[String]("keyA=valA", "keyB=valB")) must
//        beEqualTo("keyA=valA&keyB=valB")
//    }
//    "URL escape" in {
//      OauthExtractor.combineOauthParams(Array[String]("key A=val A", "keyB=Ú")) must
//        beEqualTo("key%20A=val%20A&keyB=%C3%9A")
//    }
//    "Sort alphabetically" in {
//      OauthExtractor.combineOauthParams(Array[String]("keyC=valC", "keyC=valB", "keyA=valA")) must
//        beEqualTo("keyA=valA&keyC=valB&keyC=valC")
//    }
//  }
}

object OauthExtractorSpec {

  val NormalCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
  val IllegalCharacters = " !\"#$%&\'()*+,/:;<=>?@"
  val IllegalCharactersEncoded = "%20%21%22%23%24%25%26%27%28%29%2A%2B%2C%2F%3A%3B%3C%3D%3E%3F%40"
  val DoubleByteCharacters = "áéő"
  val DoubleByteCharactersEncoded = "%C3%A1%C3%A9%C5%91"
}
