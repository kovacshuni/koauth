package com.hunorkovacs.koauth.service.provider

import java.util.{Calendar, TimeZone}

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics._

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}

trait Verifier {

  def verifyForRequestToken(request: Request)
                           (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]

  def verifyForAccessToken(request: Request)
                          (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]

  def verifyForOauthenticate(request: Request)
                            (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]

  def verifyForAuthorize(request: Request)
                        (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]
}

protected object DefaultVerifier extends Verifier {

  private val HmacReadable = "HMAC-SHA1"
  private val TimePrecisionMillis = 10 * 60 * 1000
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

  def verifyForRequestToken(request: Request)
            (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification] = {
    Future(verifyRequiredParams(request, RequestTokenRequiredParams)) flatMap {
      case nok: VerificationNok => successful(nok)
      case VerificationOk =>
        persistence.getConsumerSecret(request.oauthParamsMap(consumerKeyName)) flatMap {
          case None => successful(VerificationFailed(MessageInvalidConsumerKey))
          case Some(consumerSecret) => fourVerifications(request, consumerSecret, "", "")
        }
    }
  }

  def verifyForAccessToken(request: Request)
                          (implicit persistence: Persistence, ec: ExecutionContext) =
    verifyWithToken(request, AccessTokenRequiredParams, persistence.getRequestTokenSecret)

  def verifyForOauthenticate(request: Request)
                            (implicit persistence: Persistence, ec: ExecutionContext) =
    verifyWithToken(request, OauthenticateRequiredParams, persistence.getAccessTokenSecret)

  def verifyWithToken(request: Request,
                      requiredParams: List[String],
                      getSecret: (String, String) => Future[Option[String]])
                     (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification] = {
    Future(verifyRequiredParams(request, requiredParams)) flatMap {
      case nok: VerificationNok => successful(nok)
      case VerificationOk =>
        val consumerKeyF = Future(request.oauthParamsMap(consumerKeyName))
        consumerKeyF flatMap { consumerKey =>
          persistence.getConsumerSecret(consumerKey) flatMap {
            case None => successful(VerificationFailed(MessageInvalidConsumerKey))
            case Some(someConsumerSecret) =>
              Future(request.oauthParamsMap(tokenName)) flatMap { token =>
                getSecret(consumerKey, token) flatMap {
                  case None => successful(VerificationFailed(MessageInvalidToken))
                  case Some(someTokenSecret) => fourVerifications(request, someConsumerSecret, token, someTokenSecret)
                }
              }
          }
        }
    }
  }

  def verifyForAuthorize(request: Request)
                        (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification] = {
    Future(verifyRequiredParams(request, AuthorizeRequiredParams)) flatMap {
      case nok: VerificationNok => successful(nok)
      case VerificationOk =>
        Future {
          (request.oauthParamsMap(usernameName), request.oauthParamsMap(passwordName))
        } flatMap { args =>
          val (username, password) = args
          persistence.authenticate(username, password)
        } map {
          case false => VerificationFailed(MessageInvalidCredentials)
          case true => VerificationOk
        }
    }
  }

  private def fourVerifications(request: Request, consumerSecret: String, token: String, tokenSecret: String)
                               (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification] = {
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

  def verifySignature(request: Request, consumerSecret: String, tokenSecret: String): Verification = {
    val signatureBase = concatItemsForSignature(request)
    val computedSignature = sign(signatureBase, consumerSecret, tokenSecret)
    val sentSignature = urlDecode(request.oauthParamsMap(signatureName))
    if (sentSignature.equals(computedSignature)) VerificationOk
    else VerificationFailed(MessageInvalidSignature)
  }

  def verifyNonce(request: Request, token: String)
                 (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification] = {
    Future {
      val nonce = request.oauthParamsMap(nonceName)
      val consumerKey = request.oauthParamsMap(consumerKeyName)
      (nonce, consumerKey)
    } flatMap { args =>
      val (nonce, consumerKey) = args
      persistence.nonceExists(nonce, consumerKey, token) map { exists =>
        if (exists) VerificationFailed(MessageInvalidNonce)
        else VerificationOk
      }
    }
  }

  def verifyTimestamp(request: Request): Verification = {
    val timestamp = request.oauthParamsMap(timestampName)
    try {
      val actualStamp = timestamp.toLong
      val expectedStamp = CalendarGMT.getTimeInMillis
      if (Math.abs(actualStamp - expectedStamp) <= TimePrecisionMillis) VerificationOk
      else VerificationFailed(MessageInvalidTimestamp)
    } catch {
      case nfEx: NumberFormatException => VerificationUnsupported("Invalid timestamp format.")
    }
  }

  def verifyAlgorithm(request: Request): Verification = {
    val signatureMethod = request.oauthParamsMap(signatureMethodName)
    if (HmacReadable != signatureMethod) VerificationUnsupported(MessageUnsupportedMethod)
    else VerificationOk
  }

  def verifyRequiredParams(request: Request, requiredParams: List[String]): Verification = {
    val paramsKeys = request.oauthParamsList.map(e => e._1)
    if (requiredParams.equals(paramsKeys.sorted)) VerificationOk
    else VerificationUnsupported(MessageParameterMissing +
      (paramsKeys.diff(requiredParams) ::: requiredParams.diff(paramsKeys)).mkString(", "))
  }
}

object VerifierFactory {

  def getDefaultOauthVerifier = DefaultVerifier
}
