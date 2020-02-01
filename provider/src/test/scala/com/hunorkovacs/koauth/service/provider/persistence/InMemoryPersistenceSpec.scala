package com.hunorkovacs.koauth.service.provider.persistence

import org.specs2.concurrent.ExecutionEnv

import scala.concurrent.ExecutionContext

class InMemoryPersistenceSpec(implicit ee: ExecutionEnv) extends PersistenceSpec(new InMemoryPersistence(ExecutionContext.Implicits.global))
