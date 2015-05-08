package com.hunorkovacs.koauthsync.service.provider

import com.hunorkovacs.koauth.domain.{KoauthResponse, KoauthRequest}
import com.hunorkovacs.koauth.service.{DefaultTokenGenerator, TokenGenerator}
import com.hunorkovacs.koauth.service.provider.persistence.Persistence

import scala.concurrent.{Await, ExecutionContext}
import scala.concurrent.duration._

trait ProviderService {

  def requestToken(request: KoauthRequest): KoauthResponse

  def accessToken(request: KoauthRequest): KoauthResponse

  def oauthenticate(request: KoauthRequest): Either[KoauthResponse, String]
}

protected class CustomProviderService(private val persistence: Persistence,
                                      private val generator: TokenGenerator,
                                      private val ec: ExecutionContext) extends ProviderService {

  private val asyncProvider = com.hunorkovacs.koauth.service.provider.ProviderServiceFactory
    .createProviderService(persistence, generator, ec)

  override def requestToken(request: KoauthRequest): KoauthResponse =
    Await.result(asyncProvider.requestToken(request), 2 seconds)

  override def accessToken(request: KoauthRequest): KoauthResponse =
    Await.result(asyncProvider.accessToken(request), 2 seconds)

  override def oauthenticate(request: KoauthRequest): Either[KoauthResponse, String] =
    Await.result(asyncProvider.oauthenticate(request), 2 seconds)
}

object ProviderServiceFactory {

  def createProviderService(persistence: Persistence, generator: TokenGenerator, ec: ExecutionContext): ProviderService =
    new CustomProviderService(persistence, generator, ec)

  def createProviderService(persistence: Persistence, ec: ExecutionContext): ProviderService =
    new CustomProviderService(persistence, DefaultTokenGenerator, ec)
}
