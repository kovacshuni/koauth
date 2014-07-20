package com.hunorkovacs.koauth.service

import javax.crypto.Mac
import java.nio.charset.Charset
import javax.crypto.spec.SecretKeySpec
import java.util.{TimeZone, Calendar, Base64}

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.Request
import com.hunorkovacs.koauth.service.OauthCombiner._
import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.service.OauthExtractor.UTF8

trait OauthVerifier {

  def verifyForRequestToken(enhancedRequest: Request)
                           (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification]

  def verifyForAccessToken(enhancedRequest: Request)
                          (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification]

  def verifyForOauthenticate(enhancedRequest: Request)
                            (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification]

  def verifyForAuthorize(enhancedRequest: Request)
                        (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification]
}

protected object DefaultOauthVerifier extends OauthVerifier {

  private val HmacSha1Algorithm = "HmacSHA1"
  private val HmacReadable = "HMAC-SHA1"
  private val TimePrecisionMillis = 10 * 60 * 1000
  private val UTF8Charset = Charset.forName(UTF8)
  private val Base64Encoder = Base64.getEncoder
  private val CalendarGMT = Calendar.getInstance(TimeZone.getTimeZone("GMT"))

  final val RequestTokenRequiredParams = List[String](consumerKeyName, signatureMethodName, signatureName,
    timestampName, nonceName, versionName, callbackName).sorted
  final val AuthorizeRequiredParams = List[String](consumerKeyName, tokenName, usernameName, passwordName).sorted
  final val AccessTokenRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName, verifierName).sorted
  final val OauthenticateRequiredParams = List[String](consumerKeyName, tokenName, signatureMethodName,
    signatureName, timestampName, nonceName, versionName).sorted

  val MessageInvalidConsumerKey = "Consumer Key does not exist."
  val MessageInvalidToken = "Token with Consumer Key does not exist."
  val MessageInvalidSignature = "Signature does not match."
  val MessageInvalidNonce = "Nonce was already used."
  val MessageInvalidTimestamp = "Timestamp falls outside the tolerated interval."
  val MessageUnsupportedMethod = "Unsupported Signature Method."
  val MessageParameterMissing = "OAuth parameter is missing, or duplicated. Difference: "
  val MessageNotAuthorized = "Request Token not authorized."
  val MessageInvalidCredentials = "Invalid user credentials."

  def verifyForRequestToken(enhancedRequest: Request)
            (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    verifyRequiredParams(enhancedRequest, RequestTokenRequiredParams) flatMap {
      case nok: VerificationNok => Future.successful(nok)
      case VerificationOk =>
        Future(enhancedRequest.oauthParamsMap(consumerKeyName)).flatMap(persistence.getConsumerSecret) flatMap {
          case None => Future(VerificationFailed(MessageInvalidConsumerKey))
          case Some(consumerSecret) =>
            Future.sequence(List(verifySignature(enhancedRequest, consumerSecret, tokenSecret = ""),
              verifyAlgorithm(enhancedRequest),
              verifyTimestamp(enhancedRequest),
              verifyNonce(enhancedRequest, ""))) map { list =>
                list.collectFirst({ case nok: VerificationNok => nok }).getOrElse(VerificationOk)
              }
          }
      }
  }

  def verifyForAccessToken(enhancedRequest: Request)
                          (implicit persistence: OauthPersistence, ec: ExecutionContext) =
    verifyWithToken(enhancedRequest, AccessTokenRequiredParams, persistence.getRequestTokenSecret)

  def verifyForOauthenticate(enhancedRequest: Request)
                            (implicit persistence: OauthPersistence, ec: ExecutionContext) =
    verifyWithToken(enhancedRequest, OauthenticateRequiredParams, persistence.getAccessTokenSecret)

  def verifyWithToken(enhancedRequest: Request,
                      requiredParams: List[String],
                      getSecret: (String, String) => Future[Option[String]])
                     (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    verifyRequiredParams(enhancedRequest, requiredParams) flatMap {
      case nok: VerificationNok => Future.successful(nok)
      case VerificationOk =>
        for {
          consumerKey <- Future(enhancedRequest.oauthParamsMap(consumerKeyName))
          consumerSecret <- persistence.getConsumerSecret(consumerKey)
          ver1 <- consumerSecret match {
            case None => Future(VerificationFailed(MessageInvalidConsumerKey))
            case Some(someConsumerSecret) =>
              for {
                token <- Future(enhancedRequest.oauthParamsMap(tokenName))
                tokenSecret <- getSecret(consumerKey, token)
                ver2 <- tokenSecret match {
                  case None => Future(VerificationFailed(MessageInvalidToken))
                  case Some(someTokenSecret) =>
                    val signatureF = verifySignature(enhancedRequest, someConsumerSecret, someTokenSecret)
                    val algorithmF = verifyAlgorithm(enhancedRequest)
                    val timestampF = verifyTimestamp(enhancedRequest)
                    val nonceF = verifyNonce(enhancedRequest, token)
                    Future.sequence(List(signatureF, algorithmF, timestampF, nonceF)) map { list =>
                      list.collectFirst({ case nok: VerificationNok => nok})
                        .getOrElse(VerificationOk)
                    }
                }
              } yield ver2
          }
        } yield ver1
    }
  }

  def verifyForAuthorize(enhancedRequest: Request)
                        (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    verifyRequiredParams(enhancedRequest, AuthorizeRequiredParams) flatMap {
      case nok: VerificationNok => Future.successful(nok)
      case VerificationOk =>
        val username = enhancedRequest.oauthParamsMap(usernameName)
        val password = enhancedRequest.oauthParamsMap(passwordName)
        persistence.authenticate(username, password) map {
          case false => VerificationFailed(MessageInvalidCredentials)
          case true => VerificationOk
        }
    }
  }

  def verifySignature(enhancedRequest: Request, consumerSecret: String, tokenSecret: String)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    for {
      signatureBase <- concatItemsForSignature(enhancedRequest)
      computedSignature <- sign(signatureBase, consumerSecret, tokenSecret)
    } yield {
      val sentSignature = OauthExtractor.urlDecode(enhancedRequest.oauthParamsMap(signatureName))
      if (sentSignature.equals(computedSignature)) VerificationOk
      else VerificationFailed(MessageInvalidSignature)
    }
  }

  def verifyNonce(enhancedRequest: Request, token: String)
                 (implicit persistence: OauthPersistence, ec: ExecutionContext): Future[Verification] = {
    Future {
      val nonce = enhancedRequest.oauthParamsMap(nonceName)
      val consumerKey = enhancedRequest.oauthParamsMap(consumerKeyName)
      (nonce, consumerKey)
    } flatMap { t =>
      persistence.nonceExists(t._1, t._2, token)
    } map { exists =>
      if (exists) VerificationFailed(MessageInvalidNonce)
      else VerificationOk
    }
  }

  def verifyTimestamp(enhancedRequest: Request)
                              (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val timestamp = enhancedRequest.oauthParamsMap(timestampName)
      try {
        val actualStamp = timestamp.toLong
        val expectedStamp = CalendarGMT.getTimeInMillis
        if (Math.abs(actualStamp - expectedStamp) <= TimePrecisionMillis) VerificationOk
        else VerificationFailed(MessageInvalidTimestamp)
      } catch {
        case nfEx: NumberFormatException => VerificationUnsupported("Invalid timestamp format.")
      }
    }
  }

  def verifyAlgorithm(enhancedRequest: Request)
                     (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val signatureMethod = enhancedRequest.oauthParamsMap(signatureMethodName)
      if (HmacReadable != signatureMethod) VerificationUnsupported(MessageUnsupportedMethod)
      else VerificationOk
    }
  }

  def verifyRequiredParams(enhancedRequest: Request, requiredParams: List[String])
                          (implicit ec: ExecutionContext): Future[Verification] = {
    Future {
      val paramsKeys = enhancedRequest.oauthParamsList.map(e => e._1)
      if (requiredParams.equals(paramsKeys.sorted)) VerificationOk
      else VerificationUnsupported(MessageParameterMissing +
        (paramsKeys.diff(requiredParams) ::: requiredParams.diff(paramsKeys)).mkString(", "))
    }
  }

  def sign(base: String, consumerSecret: String, tokenSecret: String)
          (implicit ec: ExecutionContext): Future[String] = {
    Future {
      val key = encodeConcat(List(consumerSecret, tokenSecret))
      val secretkeySpec = new SecretKeySpec(key.getBytes(UTF8Charset), HmacSha1Algorithm)
      val mac = Mac.getInstance(HmacSha1Algorithm)
      mac.init(secretkeySpec)
      val bytesToSign = base.getBytes(UTF8Charset)
      val digest = mac.doFinal(bytesToSign)
      val digest64 = Base64Encoder.encode(digest)
      new String(digest64, UTF8Charset)
    }
  }
}

object OauthVerifierFactory {

  def getDefaultOauthVerifier = DefaultOauthVerifier
}
