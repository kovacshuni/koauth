package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain.{KoauthRequest, VerificationFailed, VerificationOk, VerificationUnsupported}
import com.hunorkovacs.koauth.service.Arithmetics.{sign, urlEncode}
import com.hunorkovacs.koauth.service.provider.VerifierFactory.getDefaultOauthVerifier
import org.specs2.mock.Mockito
import org.specs2.mutable._

import scala.concurrent.Await
import scala.concurrent.Future.successful
import scala.concurrent.duration._

class VerifierSpec extends Specification with Mockito {

  val Username = "username123"
  val Password = "username!@#"
  val SignatureBase = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val SignatureBase2 = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_callback%3Dhttps%3A%2F%2Ftwitter.com%2Fcallback%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"
  val SignatureBase3 = "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json" +
    "&include_entities%3Dtrue" +
    "%26oauth_callback%3Dhttps%3A%2F%2Ftwitter.com%2Fcallback" +
    "%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog" +
    "%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg" +
    "%26oauth_signature_method%3DHMAC-SHA1" +
    "%26oauth_timestamp%3D1318622958" +
    "%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb" +
    "%26oauth_version%3D1.0%26" +
    "%26password%3D" + urlEncode(Password) + "%26" +
    "%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521" +
    "%26username%3D" + urlEncode(Username) + "%26"
  val ConsumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
  val TokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
  val Signature = "tnnArxj06cWHq44gCs1OSKk/jLY="
  val Signature2 = "R3Q96/3CQBYAGbsPvvOliJLifnI="
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
  val OauthParamsList2 = List(("oauth_consumer_key", ConsumerKey),
    ("oauth_timestamp", "1318622958"),
    ("oauth_nonce", Nonce),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_signature", Signature2),
    ("oauth_callback", "https://twitter.com/callback"),
    ("oauth_version", "1.0"))
  val OauthParamsList3 = OauthParamsList
    .filterNot(p => p._1 == "oauth_signature")
    .:::(List(("oauth_token", Token),
      ("username", Username),
      ("password", Password),
      ("oauth_signature", "(*&")))

  val verifier = getDefaultOauthVerifier
  import verifier._

  "Verifying signature" should {
    "return positive verification if signature matches." in {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationOk)
    }
    "return negative verification if signature doesn't match." in {
      val paramsList = OauthParamsList.filterNot(e => "oauth_signature".equals(e._1))
        .::(("oauth_signature", "123456"))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifySignature(request, ConsumerSecret, TokenSecret) must
        equalTo (VerificationFailed(MessageInvalidSignature))
    }
  }

  "Verifying signature method" should {
    "return positive verification if method is HMAC-SHA1." in {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)
      verifyAlgorithm(request) must equalTo (VerificationOk)
    }
    "return unsupported verification if method is other than HMAC-SHA1." in {
      val paramsList = OauthParamsList.filterNot(e => "oauth_signature_method".equals(e._1))
        .::(("oauth_signature_method", "MD5"))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifyAlgorithm(request) must equalTo (VerificationUnsupported(MessageUnsupportedMethod))
    }
  }

  "Verifying timestamp" should {
    "return positive verification if timestamp equals current time." in {
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", now.toString))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifyTimestamp(request) must equalTo (VerificationOk)
    }
    "return positive verification if timestamp is 9 minutes late." in {
      val nineMinutesAgo = now - 9 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifyTimestamp(request) must equalTo (VerificationOk)
    }
    "return positive verification if timestamp is 9 minutes ahead." in {
      val nineMinutesAgo = now + 9 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifyTimestamp(request) must equalTo (VerificationOk)
    }
    "return negative verification if timestamp is 11 minutes late." in {
      val nineMinutesAgo = now - 11 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifyTimestamp(request) must equalTo (VerificationFailed(MessageInvalidTimestamp))
    }
    "return negative verification if timestamp is 11 minutes ahead." in {
      val nineMinutesAgo = now + 11 * 60 * 1000
      val paramsList = OauthParamsList.filterNot(e => "oauth_timestamp".equals(e._1))
        .::(("oauth_timestamp", nineMinutesAgo.toString))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      verifyTimestamp(request) must equalTo (VerificationFailed(MessageInvalidTimestamp))
    }
  }

  "Verifying nonce" should {
    "return positive verification if nonce doesn't exist for same consumer key and token." in new commonMocks {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      verifyNonce(request, Token) must equalTo (VerificationOk).await
    }
    "return negative verification if nonce exists for same consumer key and token." in new commonMocks {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(true)

      verifyNonce(request, Token) must equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
  }

  "Verifying required parameters" should {
    "return positive if lists are the same but shuffled." in {
      val request = createRequest(List(("b", "2"), ("a", "1")))
      verifyRequiredParams(request, List("a", "b")) must beEqualTo (VerificationOk)
    }
    "return negative if parameter is missing and state which." in {
      val request = createRequest(List(("a", "1")))
      verifyRequiredParams(request, List("a", "b")) must
        beEqualTo (VerificationUnsupported(MessageParameterMissing + "b"))
    }
    "return negative if duplicate parameter and state which." in {
      val request = createRequest(List(("a", "1"), ("b", "2"), ("b", "3")))
      verifyRequiredParams(request, List("a", "b")) must
        beEqualTo (VerificationUnsupported(MessageParameterMissing + "b"))
    }
    "return negative if additional parameter and state which." in {
      val request = createRequest(List(("a", "1"), ("b", "2"), ("c", "3")))
      verifyRequiredParams(request, List("a", "b")) must
        beEqualTo (VerificationUnsupported(MessageParameterMissing + "c"))
    }
    def createRequest(paramsList: List[(String, String)]) = KoauthRequest("", "", List.empty, List.empty, paramsList)
  }

  "Verifying the four verifications" should {
    "return positive if signature, method, timestamp, nonce all ok." in new commonMocks {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase, time)
      val signature = sign(signatureBase, ConsumerSecret, Token)
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      fourVerifications(request, ConsumerSecret, Token, TokenSecret) must
        equalTo (VerificationOk).await
    }
    "return negative if method, timestamp, nonce all ok but signature is invalid." in new commonMocks {
      val time = now
      val paramsList = actualizeParamsList(OauthParamsList, "#:|^*&invalidsignature", time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      fourVerifications(request, ConsumerSecret, Token, TokenSecret) must
        equalTo (VerificationFailed(MessageInvalidSignature)).await
    }
    "return negative if signature, method, nonce all ok but timestamp late." in new commonMocks {
      val time = now - 11 * 60 * 1000
      val signatureBase = actualizeSignatureBase(SignatureBase, time)
      val signature = sign(signatureBase, ConsumerSecret, Token)
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      fourVerifications(request, ConsumerSecret, Token, TokenSecret) must
        equalTo (VerificationFailed(MessageInvalidTimestamp)).await
    }
    "return negative if signature, method, timestamp all ok but nonce exists" in new commonMocks {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase, time)
      val signature = sign(signatureBase, ConsumerSecret, "")
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(true)

      fourVerifications(request, ConsumerSecret, Token, TokenSecret) must
        equalTo (VerificationFailed(MessageInvalidNonce)).await
    }
    "return unsupported if signature, timestamp, nonce all ok but method is different from hmac-sha1." in new commonMocks {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase, time)
        .replaceFirst("%26oauth_signature_method%3DHMAC-SHA1", "%26oauth_signature_method%3DMD5")
      val signature = sign(signatureBase, ConsumerSecret, Token)
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
        .filterNot(e => "oauth_signature_method".equals(e._1))
        .::(("oauth_signature_method", "MD5"))
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      fourVerifications(request, ConsumerSecret, Token, TokenSecret) must
        equalTo (VerificationUnsupported(MessageUnsupportedMethod)).await
    }
  }

  def actualizeSignatureBase(base: String, time: Long) = {
    base.replaceFirst("oauth_timestamp%3D1318622958%26", s"oauth_timestamp%3D$time%26")
      .replaceFirst("%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", "")
  }

  private def actualizeParamsList(paramsList: List[(String, String)], signature: String, time: Long) = {
    (paramsList filterNot { e: (String, String) =>
      "oauth_signature".equals(e._1) ||
        "oauth_timestamp".equals(e._1)
    }).::(("oauth_signature", signature))
      .::(("oauth_timestamp", time.toString))
  }

  "Verifying the 'Request Token' request" should {
    "return positive Consumer Key exists." in new commonMocks {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase2, time)
      val signature = sign(signatureBase, ConsumerSecret, "")
      val paramsList = actualizeParamsList(OauthParamsList2, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.nonceExists(Nonce, ConsumerKey, "") returns successful(false)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))

      verifyForRequestToken(request) must equalTo (VerificationOk).await
    }
    "return negative if Consumer Key is not registered." in new commonMocks {
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(None)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList2)

      verifyForRequestToken(request) must equalTo (VerificationFailed(MessageInvalidConsumerKey)).await
    }
    "return negative if required parameter is missing." in new commonMocks {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)

      (Await.result(verifyForRequestToken(request), 1.0 second) match {
        case VerificationUnsupported(message) => message
        case _ => ""
      }) must startingWith(MessageParameterMissing)
    }
  }

  "Verifying the requests with Token" should {
    "return positive if signature, method, timestamp, nonce all ok." in new commonMocks  {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase, time)
      val signature = sign(signatureBase, ConsumerSecret, TokenSecret)
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)

      verifyWithToken(request, OauthenticateRequiredParams, getSecret) must equalTo (VerificationOk).await
    }
    "return negative if consumer key doesn't exist." in new commonMocks {
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(None)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)

      verifyWithToken(request, OauthenticateRequiredParams, getSecret) must equalTo (VerificationFailed(MessageInvalidConsumerKey)).await
    }
    "return negative if token with consumer key doesn't exist." in new commonMocks {
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      def cantGetSecret(consumerKey: String, token: String) = successful(None)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)

      verifyWithToken(request, OauthenticateRequiredParams, cantGetSecret) must equalTo (VerificationFailed(MessageInvalidToken)).await
    }
    "return negative if required parameter is missing." in new commonMocks {
      val params = OauthParamsList2.filterNot(p => p._1 == "oauth_version")
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, params)

      val verification = Await.result(verifyWithToken(request, OauthenticateRequiredParams, getSecret), 1.0 second)

      val message = verification match {
        case VerificationUnsupported(m) => m must startingWith(MessageParameterMissing)
        case _ => failure("result is not of type " + VerificationUnsupported.getClass.getSimpleName)
      }
    }

    def getSecret(consumerKey: String, token: String) = {
      if (ConsumerKey == consumerKey && Token == token) successful(Some(TokenSecret))
      else successful(None)
    }
  }

  "Verifying for authorization" should {
    "return positive if user credentials are valid, consumer key with token registered." in new commonMocks {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase3, time)
      val signature = sign(signatureBase, ConsumerSecret, TokenSecret)
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.getRequestTokenSecret(ConsumerKey, Token) returns successful(Some(TokenSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)
      mockedPer.authenticate(Username, Password) returns successful(true)

      verifyForAuthorize(request) must equalTo (VerificationOk).await
    }
    "return negative if user credentials are invalid, consumer key with token registered." in new commonMocks {
      val time = now
      val signatureBase = actualizeSignatureBase(SignatureBase3, time)
      val signature = sign(signatureBase, ConsumerSecret, TokenSecret)
      val paramsList = actualizeParamsList(OauthParamsList, signature, time)
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, paramsList)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.getRequestTokenSecret(ConsumerKey, Token) returns successful(Some(TokenSecret))
      mockedPer.nonceExists(Nonce, ConsumerKey, Token) returns successful(false)
      mockedPer.authenticate(Username, Password) returns successful(false)

      verifyForAuthorize(request) must equalTo (VerificationFailed(MessageInvalidCredentials)).await
    }
    "return negative if consumer key not registered, user credentials are ok." in new commonMocks {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(None)

      verifyForAuthorize(request) must equalTo (VerificationFailed(MessageInvalidConsumerKey)).await
    }
    "return negative if Consumer Key with Request Token not registered, user credentials are ok." in new commonMocks {
      val request = KoauthRequest(Method, Url, UrlParams, BodyParams, OauthParamsList)
      mockedPer.getConsumerSecret(ConsumerKey) returns successful(Some(ConsumerSecret))
      mockedPer.getRequestTokenSecret(ConsumerKey, Token) returns successful(None)

      verifyForAuthorize(request) must equalTo (VerificationFailed(MessageInvalidToken)).await
    }
    "return negative if request parameter is missing or duplicate." in new commonMocks {
      val params = OauthParamsList3.filterNot(p => p._1 == "oauth_consumer_key")
      val request = KoauthRequest("", "", List.empty, List.empty, params)
      mockedPer.authenticate(Username, Password) returns successful(false)

      verifyForAuthorize(request) must equalTo (VerificationUnsupported(MessageParameterMissing + "oauth_consumer_key")).await
    }
  }

  private def now = System.currentTimeMillis() / 1000

  private trait commonMocks extends Before with Mockito {
    implicit lazy val mockedPer = mock[Persistence]

    override def before = Nil
  }
}
