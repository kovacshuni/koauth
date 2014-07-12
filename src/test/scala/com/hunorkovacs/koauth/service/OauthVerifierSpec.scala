package com.hunorkovacs.koauth.service

import java.util.{TimeZone, Calendar}

import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthCombiner.urlEncode
import com.hunorkovacs.koauth.service.OauthVerifier._
import org.mockito.Mockito.{when, mock}
import org.specs2.mutable._

import scala.concurrent.Future

class OauthVerifierSpec extends Specification {

  val SignatureBase = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val ConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val Token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val Nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"

  val Method = "POST"
  val Url = "https://api.twitter.com/1/statuses/update.json"
  val UrlParams = List(("include_entities", "true"))
  val BodyParams = List(("status", "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"))
  val OauthParamsList = List(("oauth_consumer_key", ConsumerKey),
  ("oauth_token", Token),
  ("oauth_timestamp", "1318622958"),
  ("oauth_nonce", Nonce),
  ("oauth_signature_method", "HMAC-SHA1"),
  ("oauth_signature", Signature),
  ("oauth_version", "1.0"))

  "Singing a signature base with two secrets" should {
    "give the correct signature." in {
      sign(SignatureBase, ConsumerSecret, TokenSecret) must
        equalTo (Signature).await
    }
  }

  "Verifying signature" should {
    "return positive verification if signature matches." in {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationOk).await
    }
    "return negative verification if signature doesn't match." in {
      val paramsList = OauthParamsList.filterNot(e => "oauth_signature".equals(e._1))
        .::(("oauth_signature", "123456"))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationFailed(MessageInvalidSignature)).await
    }
  }

  "Verifying signature method" should {
    "return positive verification if method is HMAC-SHA1." in {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)
      verifyAlgorithm(request) must equalTo (VerificationOk).await
    }
    "return unsupported verification if method is other than HMAC-SHA1." in {
      val paramsList = OauthParamsList.filterNot(e => "oauth_signature_method".equals(e._1))
        .::(("oauth_signature_method", "MD5"))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyAlgorithm(request) must equalTo (VerificationUnsupported(MessageUnsupportedMethod)).await
    }
  }

  "Verifying timestamp" should {
    "return positive verification if timestamp equals current time." in {
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis.toString))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationOk).await
    }
    "return positive verification if timestamp is 9 minutes late." in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 9 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationOk).await
    }
    "return positive verification if timestamp is 9 minutes ahead." in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis + 9 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationOk).await
    }
    "return negative verification if timestamp is 11 minutes late." in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 11 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
    "return negative verification if timestamp is 11 minutes ahead." in {
      val nineMinutesAgo = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis + 11 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyTimestamp(request) must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
  }

  "Verifying nonce" should {
    "return positive verification if nonce doesn't exist for same consumer key and token." in {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.nonceExists(Nonce, ConsumerKey, Token)).thenReturn(Future(false))
      verifyNonce(request, Token) must equalTo (VerificationOk).await
    }
    "return negative verification if nonce exists for same consumer key and token." in {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.nonceExists(Nonce, ConsumerKey, Token)).thenReturn(Future(true))
      verifyNonce(request, Token) must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
  }

  "Verifying the 'Request Token' request" should {
    "return positive if signature, method, timestamp, nonce all ok." in {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.getConsumerSecret(ConsumerKey)).thenReturn(Future(Some(ConsumerSecret)))
      when(pers.nonceExists(Nonce, ConsumerKey, "")).thenReturn(Future(false))
      val signatureF = sign(signatureBase, ConsumerSecret, "")
      val verificationF = signatureF flatMap { signature =>
        val encodedSignature = urlEncode(signature)
        val paramsList = (OauthParamsList filterNot { e: (String, String) =>
          "oauth_signature".equals(e._1) ||
            "oauth_token".equals(e._1) ||
            "oauth_timestamp".equals(e._1)
        }).::(("oauth_signature", encodedSignature))
          .::(("oauth_timestamp", time.toString))
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationOk).await
    }
    "return negative if method, timestamp, nonce all ok but signature is invalid." in {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.getConsumerSecret(ConsumerKey)).thenReturn(Future(Some(ConsumerSecret)))
      when(pers.nonceExists(Nonce, ConsumerKey, "")).thenReturn(Future(false))
      val invalidSignature = urlEncode("123lkjh")
      val paramsList = (OauthParamsList filterNot { e: (String, String) =>
        "oauth_signature".equals(e._1) ||
          "oauth_token".equals(e._1) ||
          "oauth_timestamp".equals(e._1)
      }).::(("oauth_signature", invalidSignature))
        .::(("oauth_timestamp", time.toString))
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
      verifyForRequestToken(request) must equalTo (VerificationFailed(MessageInvalidSignature)).await
    }
    "return negative if signature, method, nonce all ok but timestamp late." in {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 11 * 60 * 1000
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.getConsumerSecret(ConsumerKey)).thenReturn(Future(Some(ConsumerSecret)))
      when(pers.nonceExists(Nonce, ConsumerKey, "")).thenReturn(Future(false))
      val signatureF = sign(signatureBase, ConsumerSecret, "")
      val verificationF = signatureF flatMap { signature =>
        val encodedSignature = urlEncode(signature)
        val paramsList = (OauthParamsList filterNot { e: (String, String) =>
          "oauth_signature".equals(e._1) ||
            "oauth_token".equals(e._1) ||
            "oauth_timestamp".equals(e._1)
        }).::(("oauth_signature", encodedSignature))
          .::(("oauth_timestamp", time.toString))
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
    "return negative if signature, method, timestamp all ok but nonce exists" in {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.getConsumerSecret(ConsumerKey)).thenReturn(Future(Some(ConsumerSecret)))
      when(pers.nonceExists(Nonce, ConsumerKey, "")).thenReturn(Future(true))
      val signatureF = sign(signatureBase, ConsumerSecret, "")
      val verificationF = signatureF flatMap { signature =>
        val encodedSignature = urlEncode(signature)
        val paramsList = (OauthParamsList filterNot { e: (String, String) =>
          "oauth_signature".equals(e._1) ||
            "oauth_token".equals(e._1) ||
            "oauth_timestamp".equals(e._1)
        }).::(("oauth_signature", encodedSignature))
          .::(("oauth_timestamp", time.toString))
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
    "return unsupported if signature, timestamp, nonce all ok but method is different from hmac-sha1." in {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
        .replaceFirst("%26oauth_signature_method%3DHMAC-SHA1", "%26oauth_signature_method%3DMD5")
      implicit val pers = mock(classOf[OauthPersistence])
      when(pers.getConsumerSecret(ConsumerKey)).thenReturn(Future(Some(ConsumerSecret)))
      when(pers.nonceExists(Nonce, ConsumerKey, "")).thenReturn(Future(false))
      val signatureF = sign(signatureBase, ConsumerSecret, "")
      val verificationF = signatureF flatMap { signature =>
        val encodedSignature = urlEncode(signature)
        val paramsList = (OauthParamsList filterNot { e: (String, String) =>
          "oauth_signature".equals(e._1) ||
            "oauth_token".equals(e._1) ||
            "oauth_timestamp".equals(e._1) ||
            "oauth_signature_method".equals(e._1)
        }).::(("oauth_signature", encodedSignature))
          .::(("oauth_timestamp", time.toString))
          .::(("oauth_signature_method", "MD5"))
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationUnsupported(MessageUnsupportedMethod)).await
    }
  }
}
