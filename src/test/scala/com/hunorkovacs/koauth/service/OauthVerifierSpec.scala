package com.hunorkovacs.koauth.service

import java.util.{TimeZone, Calendar}

import com.hunorkovacs.koauth.domain.EnhancedRequest
import com.hunorkovacs.koauth.service.OauthCombiner.urlEncode
import com.hunorkovacs.koauth.service.OauthVerifierFactory.getDefaultOauthVerifier
import org.specs2.mock.Mockito
import org.specs2.mutable._

import scala.concurrent.Future.successful
import scala.concurrent.Await
import scala.concurrent.duration._

class OauthVerifierSpec extends Specification with Mockito {

  val SignatureBase = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val SignatureBase2 = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_callback%3Dhttps%3A%2F%2Ftwitter.com%2Fcallback%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val Signature2 = "R3Q96/3CQBYAGbsPvvOliJLifnI="
  val ConsumerKey = "xvz1evFS4wEEPTGEFPHBog"
  val Token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb"
  val Nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"
  val Username = "username123"
  val Password = "username!@#"

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
  val OauthParamsList2 = List(("oauth_consumer_key", ConsumerKey),
    ("oauth_timestamp", "1318622958"),
    ("oauth_nonce", Nonce),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_signature", Signature2),
    ("oauth_callback", "https://twitter.com/callback"),
    ("oauth_version", "1.0"))
  val OauthParamsList3 = List(("oauth_consumer_key", ConsumerKey),
    ("oauth_token", Token),
    ("username", Username),
    ("password", Password))

  val verifier = getDefaultOauthVerifier
  import verifier._

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
    "return positive verification if nonce doesn't exist for same consumer key and token." in new commonMocks {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      verifyNonce(request, Token) must equalTo (VerificationOk).await
    }
    "return negative verification if nonce exists for same consumer key and token." in new commonMocks {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(true)

      verifyNonce(request, Token) must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
  }

  "Verifying required parameters" should {
    "return positive if lists are the same but shuffled." in {
      val request = createRequest(List(("b", "2"), ("a", "1")))
      verifyRequiredParams(request, List("a", "b")) must beEqualTo (VerificationOk).await
    }
    "return negative if parameter is missing and state which." in {
      val request = createRequest(List(("a", "1")))
      verifyRequiredParams(request, List("a", "b")) must
        beEqualTo (VerificationUnsupported(MessageParameterMissing + "b")).await
    }
    "return negative if duplicate parameter and state which." in {
      val request = createRequest(List(("a", "1"), ("b", "2"), ("b", "3")))
      verifyRequiredParams(request, List("a", "b")) must
        beEqualTo (VerificationUnsupported(MessageParameterMissing + "b")).await
    }
    "return negative if additional parameter and state which." in {
      val request = createRequest(List(("a", "1"), ("b", "2"), ("c", "3")))
      verifyRequiredParams(request, List("a", "b")) must
        beEqualTo (VerificationUnsupported(MessageParameterMissing + "c")).await
    }
    def createRequest(paramsList: List[(String, String)]) = new EnhancedRequest("", "", List.empty, List.empty, paramsList, Map.empty)
  }

  "Verifying the 'Request Token' request" should {
    "return positive if signature, method, timestamp, nonce all ok." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = actualizeSignatureBase(time)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, "") returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, "")

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationOk).await
    }
    "return negative if method, timestamp, nonce all ok but signature is invalid." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = actualizeSignatureBase(time)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, "") returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, "")
      val paramsList = actualizeParamsList(urlEncode("123lkjh"), time)
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)

      verifyForRequestToken(request) must equalTo (VerificationFailed(MessageInvalidSignature)).await
    }
    "return negative if signature, method, nonce all ok but timestamp late." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 11 * 60 * 1000
      val signatureBase = actualizeSignatureBase(time)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, "") returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, "")

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
    "return negative if signature, method, timestamp all ok but nonce exists" in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = actualizeSignatureBase(time)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, "") returns successful(true)
      val signatureF = sign(signatureBase, ConsumerSecret, "")

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
    "return unsupported if signature, timestamp, nonce all ok but method is different from hmac-sha1." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = actualizeSignatureBase(time)
        .replaceFirst("%26oauth_signature_method%3DHMAC-SHA1", "%26oauth_signature_method%3DMD5")
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, "") returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, "")

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
          .filterNot(e => "oauth_signature_method".equals(e._1))
          .::(("oauth_signature_method", "MD5"))
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyForRequestToken(request)
      }
      verificationF must equalTo (VerificationUnsupported(MessageUnsupportedMethod)).await
    }
    "return negative if consumer key is not registered." in new commonMocks {
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(None)
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList2, OauthParamsList2.toMap)

      verifyForRequestToken(request) must equalTo (VerificationFailed(MessageInvalidConsumerKey)).await
    }
    "return negative if required parameter is missing." in new commonMocks {
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)

      (Await.result(verifyForRequestToken(request), 1.0 second) match {
        case VerificationUnsupported(message) => message
        case _ => ""
      }) must startingWith(MessageParameterMissing)
    }

    def actualizeSignatureBase(time: Long) = {
      SignatureBase2.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
    }

    def actualizeParamsList(encodedSignature: String, time: Long) = {
      (OauthParamsList2 filterNot { e: (String, String) =>
        "oauth_signature".equals(e._1) ||
          "oauth_timestamp".equals(e._1)
      }).::(("oauth_signature", encodedSignature))
        .::(("oauth_timestamp", time.toString))
    }
  }

  "Verifying the requests with Token" should {
    "return positive if signature, method, timestamp, nonce all ok." in new commonMocks  {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, TokenSecret)

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyWithToken(request, OauthenticateRequiredParams, getSecret)
      }
      verificationF must equalTo (VerificationOk).await
    }
    "return negative if consumer key doesn't exist." in new commonMocks {
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(None)
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)

      verifyWithToken(request, OauthenticateRequiredParams, getSecret) must equalTo (VerificationFailed(MessageInvalidConsumerKey)).await
    }
    "return negative if token with consumer key doesn't exist." in new commonMocks {
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      def cantGetSecret(consumerKey: String, token: String) = successful(None)
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, OauthParamsList, OauthParamsList.toMap)

      verifyWithToken(request, OauthenticateRequiredParams, cantGetSecret) must equalTo (VerificationFailed(MessageInvalidToken)).await
    }
    "return negative if method, timestamp, nonce all ok but signature is invalid." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)
      val signature = "abc123"
      val paramsList = actualizeParamsList(urlEncode(signature), time)
      val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)

      verifyWithToken(request, OauthenticateRequiredParams, getSecret) must equalTo (VerificationFailed(MessageInvalidSignature)).await
    }
    "return negative if signature, method, timestamp all ok but nonce already exists." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(true)
      val signatureF = sign(signatureBase, ConsumerSecret, TokenSecret)

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyWithToken(request, OauthenticateRequiredParams, getSecret)
      }
      verificationF must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
    "return negative if signature, method, nonce all ok but timestamp is too late." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis - 11 * 60 * 1000
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, TokenSecret)

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyWithToken(request, OauthenticateRequiredParams, getSecret)
      }
      verificationF must equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
    "return negative if signature, timestamp, nonce all ok but method is other than hmac-sha1." in new commonMocks {
      val time = Calendar.getInstance(TimeZone.getTimeZone("GMT")).getTimeInMillis
      val signatureBase = SignatureBase.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
        .replaceFirst("oauth_signature_method%3DHMAC-SHA1%26", "oauth_signature_method%3DMD5%26")
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)
      val signatureF = sign(signatureBase, ConsumerSecret, TokenSecret)

      val verificationF = signatureF flatMap { signature =>
        val paramsList = actualizeParamsList(urlEncode(signature), time)
          .filterNot(e => "oauth_signature_method".equals(e._1))
          .::(("oauth_signature_method", "MD5"))
        val request = new EnhancedRequest(Method, Url, UrlParams, BodyParams, paramsList, paramsList.toMap)
        verifyWithToken(request, OauthenticateRequiredParams, getSecret)
      }
      verificationF must equalTo (VerificationUnsupported(MessageUnsupportedMethod)).await
    }

    def actualizeParamsList(encodedSignature: String, time: Long) = {
      (OauthParamsList filterNot { e: (String, String) =>
        "oauth_signature".equals(e._1) ||
          "oauth_timestamp".equals(e._1)
      }).::(("oauth_signature", encodedSignature))
        .::(("oauth_timestamp", time.toString))
    }

    def getSecret(consumerKey: String, token: String) = {
      if (ConsumerKey == consumerKey &&
        Token == token) successful(Some(TokenSecret))
      else successful(None)
    }
  }

  "Verifying for authorization" should {
    "return positive if user credentials are valid." in new commonMocks {
      val enhanced = new EnhancedRequest("", "", List.empty, List.empty, OauthParamsList3, OauthParamsList3.toMap)
      mockedPer.authenticate(Username, Password) returns successful(true)

      verifyForAuthorize(enhanced) must equalTo (VerificationOk).await
    }
    "return negative if user credentials are invalid." in new commonMocks {
      val enhanced = new EnhancedRequest("", "", List.empty, List.empty, OauthParamsList3, OauthParamsList3.toMap)
      mockedPer.authenticate(Username, Password) returns successful(false)

      verifyForAuthorize(enhanced) must equalTo (VerificationFailed(MessageInvalidCredentials)).await
    }
    "return negative if request parameter is missing or duplicate." in new commonMocks {
      val params = OauthParamsList3.filterNot(p => p._1 == "oauth_consumer_key")
      val enhanced = new EnhancedRequest("", "", List.empty, List.empty, params, params.toMap)
      mockedPer.authenticate(Username, Password) returns successful(false)

      verifyForAuthorize(enhanced) must equalTo (VerificationUnsupported(MessageParameterMissing + "oauth_consumer_key")).await
    }
  }

  private trait commonMocks extends Before with Mockito {
    implicit lazy val mockedPer = mock[OauthPersistence]

    override def before = Nil
  }
}
