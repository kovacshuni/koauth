package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics._
import com.hunorkovacs.koauth.service.provider.persistence.Persistence
import org.slf4j.LoggerFactory

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}

trait Verifier {

  def verifyForRequestToken(request: KoauthRequest): Future[Verification]

  def verifyForAccessToken(request: KoauthRequest): Future[Verification]

  def verifyForOauthenticate(request: KoauthRequest): Future[Verification]
}

protected class CustomVerifier(private val persistence: Persistence,
                               private val ec: ExecutionContext) extends Verifier {

  implicit private val implicitEc = ec
  private val EmptyString = ""
  private val logger = LoggerFactory.getLogger(classOf[CustomVerifier])

  import VerifierObject._

  def verifyForRequestToken(request: KoauthRequest): Future[Verification] = {
    Future(verifyRequiredParams(request, RequestTokenRequiredParams)) flatMap {
      case nok: VerificationNok => successful(nok)
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(ConsumerKeyName)
        persistence.getConsumerSecret(consumerKey) flatMap {
          case None =>
            logger.debug("Consumer Key {} does not exist. Request id: {}{}", consumerKey, request.id, "")
            successful(VerificationFailed(MessageInvalidConsumerKey))
          case Some(consumerSecret) => fourVerifications(request, consumerSecret, EmptyString, EmptyString)
        }
    }
  }

  def verifyForAccessToken(request: KoauthRequest) =
    verifyWithToken(request, AccessTokenRequiredParams, persistence.getRequestTokenSecret)

  def verifyForOauthenticate(request: KoauthRequest) =
    verifyWithToken(request, OauthenticateRequiredParams, persistence.getAccessTokenSecret)

  def verifyWithToken(request: KoauthRequest,
                      requiredParams: List[String],
                      getSecret: (String, String) => Future[Option[String]]): Future[Verification] = {
    Future(verifyRequiredParams(request, requiredParams)) flatMap {
      case nok: VerificationNok => successful(nok)
      case VerificationOk =>
        val consumerKeyF = Future(request.oauthParamsMap(ConsumerKeyName))
        consumerKeyF flatMap { consumerKey =>
          persistence.getConsumerSecret(consumerKey) flatMap {
            case None =>
              logger.debug("Consumer Key {} does not exist. Request id: {}{}", consumerKey, request.id, "")
              successful(VerificationFailed(MessageInvalidConsumerKey))
            case Some(someConsumerSecret) =>
              Future(request.oauthParamsMap(TokenName)) flatMap { token =>
                getSecret(consumerKey, token) flatMap {
                  case None =>
                    logger.debug("Token {} with Consumer Key {} does not exist. Request id: {}",
                      token, consumerKey, request.id)
                    successful(VerificationFailed(MessageInvalidToken))
                  case Some(someTokenSecret) => fourVerifications(request, someConsumerSecret, token, someTokenSecret)
                }
              }
          }
        }
    }
  }

  def fourVerifications(request: KoauthRequest, consumerSecret: String, token: String, tokenSecret: String): Future[Verification] = {
    verifyNonce(request, token) flatMap { nonceVerification =>
      Future {
        List(verifySignature(request, consumerSecret, tokenSecret),
          verifyAlgorithm(request),
          verifyTimestamp(request))
          .::(nonceVerification)
          .collectFirst({ case nok: VerificationNok => nok})
          .getOrElse(VerificationOk)
      }
    }
  }

  def verifySignature(request: KoauthRequest, consumerSecret: String, tokenSecret: String): Verification = {
    val signatureBase = concatItemsForSignature(request)
    val computedSignature = sign(signatureBase, consumerSecret, tokenSecret)
    val sentSignature = request.oauthParamsMap(SignatureName)
    if (sentSignature.equals(computedSignature)) VerificationOk
    else {
      logger.debug("Signature does not match. Given: {}; Computed: {}; Computed signature base: {}; Request id: {}",
        sentSignature, computedSignature, signatureBase, request.id)
      VerificationFailed(MessageInvalidSignature + signatureBase)
    }
  }

  def verifyNonce(request: KoauthRequest, token: String): Future[Verification] = {
    Future {
      val nonce = request.oauthParamsMap(NonceName)
      val consumerKey = request.oauthParamsMap(ConsumerKeyName)
      (nonce, consumerKey)
    } flatMap { args =>
      val (nonce, consumerKey) = args
      persistence.nonceExists(nonce, consumerKey, token) map { exists =>
        if (exists) {
          logger.debug("Nonce was already used: {}; Request id: {}{}", nonce, request.id, "")
          VerificationFailed(MessageInvalidNonce)
        }
        else VerificationOk
      }
    }
  }

  def verifyTimestamp(request: KoauthRequest): Verification = {
    val timestamp = request.oauthParamsMap(TimestampName)
    val expectedStamp = System.currentTimeMillis() / 1000
    try {
      val actualStamp = timestamp.toLong
      if (Math.abs(actualStamp - expectedStamp) <= TimePrecisionSeconds) VerificationOk
      else VerificationFailed(MessageInvalidTimestamp)
    } catch {
      case nfEx: NumberFormatException =>
        logger.debug("Invalid timestamp format. Given timestamp: {}; Expecting a stamp close to this: {};",
          timestamp, expectedStamp)
        logger.debug("Request id was {}", request.id)
        logger.debug("Exception was: {}", nfEx)
        VerificationUnsupported("Invalid timestamp format.")
    }
  }

  def verifyAlgorithm(request: KoauthRequest): Verification = {
    val signatureMethod = request.oauthParamsMap(SignatureMethodName)
    if (HmacReadable != signatureMethod) {
      logger.debug("Unsupported Signature Method. Given: {}; Required: {}. Request id: {}",
        signatureMethod, HmacReadable, request.id)
      VerificationUnsupported(MessageUnsupportedMethod)
    }
    else VerificationOk
  }

  def verifyRequiredParams(request: KoauthRequest, requiredParams: List[String]): Verification = {
    val paramsKeys = request.oauthParamsList.map(e => e._1)
    if (requiredParams.equals(paramsKeys.sorted)) VerificationOk
    else {
      val diff = requiredParams.diff(paramsKeys)
      logger.debug("Given OAuth parameters are not as required. Given: {}; Required: {}; Request id: {}",
        paramsKeys, requiredParams, request.id)
      VerificationUnsupported(MessageParameterMissing + (paramsKeys.diff(requiredParams) ::: diff).mkString(", "))
    }
  }
}

protected object VerifierObject {

  val HmacReadable = "HMAC-SHA1"
  val TimePrecisionSeconds = 10 * 60

  final val RequestTokenRequiredParams = List[String](ConsumerKeyName, SignatureMethodName, SignatureName,
    TimestampName, NonceName, VersionName, CallbackName).sorted
  final val AccessTokenRequiredParams = List[String](ConsumerKeyName, TokenName, SignatureMethodName,
    SignatureName, TimestampName, NonceName, VersionName, VerifierName).sorted
  final val OauthenticateRequiredParams = List[String](ConsumerKeyName, TokenName, SignatureMethodName,
    SignatureName, TimestampName, NonceName, VersionName).sorted

  val MessageInvalidConsumerKey = "Consumer Key does not exist."
  val MessageInvalidToken = "Token with Consumer Key does not exist."
  val MessageInvalidSignature = "Signature does not match. Signature base: "
  val MessageInvalidNonce = "Nonce was already used."
  val MessageInvalidTimestamp = "Timestamp falls outside the tolerated interval."
  val MessageUnsupportedMethod = "Unsupported Signature Method."
  val MessageParameterMissing = "OAuth parameter is missing, or duplicated. Difference: "
  val MessageNotAuthorized = "Request Token not authorized."
  val MessageUserInexistent = "User does not exist for given Consumer Key and Access Token."
}
