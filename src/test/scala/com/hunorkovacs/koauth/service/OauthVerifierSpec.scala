package com.hunorkovacs.koauth.service

import java.util.{TimeZone, Calendar}

import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthVerifier._
import org.mockito.Mockito
import org.mockito.Mockito.{when, mock}
import org.specs2.mutable._

import scala.concurrent.Future

class OauthVerifierSpec extends Specification {

  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val SignatureBase = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Header = "OAuth realm=\"\", oauth_version=\"1.0\", oauth_consumer_key=\"xvz1evFS4wEEPTGEFPHBog\",oauth_token=\"370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb\",oauth_timestamp=\"1404416302\",oauth_nonce=\"dMdd6X9gO5D\",oauth_signature_method=\"HMAC-SHA1\",oauth_signature=\"b4u3rbcCO5W6N7VuDsO4aSCVN60%3D\""
  val MethodGet = "GET"
  val MethodPost = "POST"
  val Url = "https://github.com/kovacshuni/koauth"
  val Url2 = "https://api.twitter.com/1/statuses/update.json"
  val RequestParamsList = List(("realm", ""),
  ("oauth_version", "1.0"),
  ("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog"),
  ("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"),
  ("oauth_timestamp", "1404416302"),
  ("oauth_nonce", "dMdd6X9gO5D"),
  ("oauth_signature_method", "HMAC-SHA1"),
  ("oauth_signature", "b4u3rbcCO5W6N7VuDsO4aSCVN60="))
  val consumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val nonce = "dMdd6X9gO5D"

  "Singing a signature base with two secrets" should {
    "give the correct signature." in {
      sign(SignatureBase, ConsumerSecret, TokenSecret) must
      equalTo (Signature).await
    }
  }

  "Verifying signature" should {
    "return positive verification if signature matches." in {
      val request = new EnhancedRequest(Header, Url, MethodGet, RequestParamsList, RequestParamsList.toMap)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationOk).await
    }
    "return negative verification if signature doesn't match." in {
      val paramsList = RequestParamsList.filterNot(e => "oauth_signature".equals(e._1)).::(("oauth_signature", "123456"))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationFailed(MessageInvalidSignature)).await
    }
  }

  "Verifying signature method" should {
    "return positive verification if method is HMAC-SHA1" in {
      val request = new EnhancedRequest(Header, Url, MethodGet, RequestParamsList, RequestParamsList.toMap)
      verifyAlgorithm(request) must equalTo (VerificationOk).await
    }
    "return unsupported verification if method is other than HMAC-SHA1" in {
      val paramsList = RequestParamsList.filterNot(e => "oauth_signature_method".equals(e._1))
        .::(("oauth_signature_method", "MD5"))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifyAlgorithm(request) must equalTo (VerificationUnsupported(MessageUnsupportedMethod)).await
    }
  }

  "Verifying timestamp" should {
    "return positive verification if timestamp equals current time." in {
      val paramsList = RequestParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis.toString))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationOk).await
    }
    "return positive verification if timestamp is 9 minutes late" in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 9 * 60 * 1000
      val paramsList = RequestParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationOk).await
    }
    "return positive verification if timestamp is 9 minutes ahead" in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis + 9 * 60 * 1000
      val paramsList = RequestParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationOk).await
    }
    "return negative verification if timestamp is 11 minutes late" in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 11 * 60 * 1000
      val paramsList = RequestParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
    "return negative verification if timestamp is 11 minutes ahead" in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis + 11 * 60 * 1000
      val paramsList = RequestParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Header, Url, MethodGet, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
  }

  "Verifying nonce" should {
    "return positive verification if nonce doesn't exist for same consumer key and token." in {
      val request = new EnhancedRequest(Header, Url, MethodGet, RequestParamsList, RequestParamsList.toMap)
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.nonceExists(nonce, consumerKey, token)).thenReturn(Future(false))
      verifyNonce(request, token) must equalTo (VerificationOk).await
    }
    "return negative verification if nonce exists for same consumer key and token." in {
      val request = new EnhancedRequest(Header, Url, MethodGet, RequestParamsList, RequestParamsList.toMap)
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.nonceExists(nonce, consumerKey, token)).thenReturn(Future(true))
      verifyNonce(request, token) must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
  }

  "Verifying the 'Request Token' request" should {
    "return positive if signature, method, timestamp, nonce all ok" in {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.getConsumerSecret(consumerKey)).thenReturn(Future(Some(ConsumerSecret)))
      when(pers.nonceExists(nonce, consumerKey, "")).thenReturn(Future(false))
      val signatureF = sign(signatureBase, ConsumerSecret, "")
      val paramListF = signatureF map { s =>
        RequestParamsList.filterNot(e => "oauth_signature".equals(e._1) || "oauth_token".equals(e._1))
          .::(("oauth_signature", s))
      }
      val requestF = paramListF map { l =>
        new EnhancedRequest(Header, Url2, MethodPost, l, l.toMap)
      }
      val verificationF = requestF flatMap { r =>
        verifyForRequestToken(r)
      }

      verificationF must equalTo (VerificationOk).await
    }
  }
}
