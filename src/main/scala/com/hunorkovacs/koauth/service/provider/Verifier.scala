package com.hunorkovacs.koauth.service.provider

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain._
import com.hunorkovacs.koauth.service.Arithmetics._

import scala.concurrent.Future.{sequence, successful}
import scala.concurrent.{ExecutionContext, Future}

trait Verifier {

  def verifyForRequestToken(request: KoauthRequest)
                           (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]

  def verifyForAccessToken(request: KoauthRequest)
                          (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]

  def verifyForOauthenticate(request: KoauthRequest)
                            (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]

  def verifyForAuthorize(request: KoauthRequest)
                        (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification]
}

protected object DefaultVerifier extends Verifier {

  private val HmacReadable = "HMAC-SHA1"
  private val TimePrecisionMillis = 10 * 60 * 1000

  final val RequestTokenRequiredParams = List[String](consumerKeyName, signatureMethodName, signatureName,
    timestampName, nonceName, versionName, callbackName).sorted
  final val AuthorizeRequiredParams = List[String](consumerKeyName, tokenName, usernameName, passwordName,
    signatureMethodName, signatureName, timestampName, nonceName, versionName).sorted
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

  def verifyForRequestToken(request: KoauthRequest)
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

  def verifyForAccessToken(request: KoauthRequest)
                          (implicit persistence: Persistence, ec: ExecutionContext) =
    verifyWithToken(request, AccessTokenRequiredParams, persistence.getRequestTokenSecret)

  def verifyForOauthenticate(request: KoauthRequest)
                            (implicit persistence: Persistence, ec: ExecutionContext) =
    verifyWithToken(request, OauthenticateRequiredParams, persistence.getAccessTokenSecret)

  def verifyWithToken(request: KoauthRequest,
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

  def verifyForAuthorize(request: KoauthRequest)
                        (implicit persistence: Persistence, ec: ExecutionContext): Future[Verification] = {
    Future(verifyRequiredParams(request, AuthorizeRequiredParams)) flatMap {
      case nok: VerificationNok => successful(nok)
      case VerificationOk =>
        val consumerKey = request.oauthParamsMap(consumerKeyName)
        persistence.getConsumerSecret(consumerKey) flatMap {
          case None => successful(VerificationFailed(MessageInvalidConsumerKey))
          case Some(someConsumerSecret) =>
            val token = request.oauthParamsMap(tokenName)
            persistence.getRequestTokenSecret(consumerKey, token) flatMap {
              case None => successful(VerificationFailed(MessageInvalidToken))
              case Some(someTokenSecret) =>
                val username = request.oauthParamsMap(usernameName)
                val password = request.oauthParamsMap(passwordName)
                persistence.authenticate(username, password) flatMap {
                  case false => successful(VerificationFailed(MessageInvalidCredentials))
                  case true => fourVerifications(request, someConsumerSecret, token, someTokenSecret)
                }
            }
        }
    }
  }

  def fourVerifications(request: KoauthRequest, consumerSecret: String, token: String, tokenSecret: String)
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

  def verifySignature(request: KoauthRequest, consumerSecret: String, tokenSecret: String): Verification = {
    val signatureBase = concatItemsForSignature(request)
    val computedSignature = sign(signatureBase, consumerSecret, tokenSecret)
    val sentSignature = urlDecode(request.oauthParamsMap(signatureName))
    if (sentSignature.equals(computedSignature)) VerificationOk
    else VerificationFailed(MessageInvalidSignature)
  }

  def verifyNonce(request: KoauthRequest, token: String)
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

  def verifyTimestamp(request: KoauthRequest): Verification = {
    val timestamp = request.oauthParamsMap(timestampName)
    try {
      val actualStamp = timestamp.toLong
      val expectedStamp = System.currentTimeMillis() / 1000
      if (Math.abs(actualStamp - expectedStamp) <= TimePrecisionMillis) VerificationOk
      else VerificationFailed(MessageInvalidTimestamp)
    } catch {
      case nfEx: NumberFormatException => VerificationUnsupported("Invalid timestamp format.")
    }
  }

  def verifyAlgorithm(request: KoauthRequest): Verification = {
    val signatureMethod = request.oauthParamsMap(signatureMethodName)
    if (HmacReadable != signatureMethod) VerificationUnsupported(MessageUnsupportedMethod)
    else VerificationOk
  }

  def verifyRequiredParams(request: KoauthRequest, requiredParams: List[String]): Verification = {
    val paramsKeys = request.oauthParamsList.map(e => e._1)
    if (requiredParams.equals(paramsKeys.sorted)) VerificationOk
    else VerificationUnsupported(MessageParameterMissing +
      (paramsKeys.diff(requiredParams) ::: requiredParams.diff(paramsKeys)).mkString(", "))
  }
}

object VerifierFactory {

  def getDefaultOauthVerifier = DefaultVerifier
}
