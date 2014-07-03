package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthVerifier.{sign, verifySignature}
import org.specs2.mutable._

class OauthVerifierSpec extends Specification {

  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val SignatureBase = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Header = "OAuth realm=\"\", oauth_version=\"1.0\", oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\",oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\",oauth_timestamp=\"1404416302\",oauth_nonce=\"dMdd6X9gO5D\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"b4u3rbcCO5W6N7VuDsO4aSCVN60%3D\""
  val RequestParamsList = List(("realm", ""),
    ("oauth_version", "1.0"),
    ("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog"),
    ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
    ("oauth_timestamp", "1404416302"),
    ("oauth_nonce", "dMdd6X9gO5D"),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_signature", "b4u3rbcCO5W6N7VuDsO4aSCVN60="))

  "Singing" should {
    "sign simple" in {
      sign(SignatureBase, ConsumerSecret, TokenSecret) must
        equalTo (Signature).await
    }
  }

  "Verifying signature " should {
    "Verify positive if signature matches" in {
      val request = new EnhancedRequest(Header, "https://github.com/kovacshuni/koauth", "GET", RequestParamsList, RequestParamsList.toMap)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationOk).await
    }
    "Verify negative if signature doesn't match" in {
      val paramsList = RequestParamsList.filterNot(e => "oauth_signature".equals(e._1)).::(("oauth_signature", "123456"))
      val request = new EnhancedRequest(Header, "https://github.com/kovacshuni/koauth", "GET", paramsList, paramsList.toMap)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationFailed).await
    }
  }
}
