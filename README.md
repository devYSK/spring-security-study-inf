# Spring Security Study Repository
> 인프런 스프링 시큐리티 강좌를(백기선님) 학습하고 정리한 내용입니다.

## [섹션 0. 스프링 시큐리티: 폼 인증](#섹션-0.-스프링-시큐리티:-폼-인증)
* [강좌 자료](#강좌-자료)
* [폼 인증 예제 살펴보기](#폼-인증-예제-살펴보기)
* [스프링 웹 프로젝트 만들기](#스프링-웹-프로젝트-만들기)
* [스프링 시큐리티 연동](#스프링-시큐리티-연동)
* [스프링 시큐리티 설정하기](#스프링-시큐리티-설정하기)
* [스프링 시큐리티 커스터마이징: 인메모리 유저 추가](#스프링-시큐리티-커스터마이징:-인메모리-유저-추가)
* [스프링 시큐리티 커스터마이징: JPA 연동](#스프링-시큐리티-커스터마이징:-JPA-연동)
* [스프링 시큐리티 커스터마이징: PasswordEncoder](#스프링-시큐리티-커스터마이징:-PasswordEncoder)
* [스프링 시큐리티 테스트 1부](#스프링-시큐리티-테스트-1부)
* [스프링 시큐리티 테스트 2부](#스프링-시큐리티-테스트-2부)

## [섹션 1. 스프링 시큐리티: 아키텍처](#섹션-1.-스프링-시큐리티:-아키텍처)
* [SecurityContextHolder와 Authentication](#SecurityContextHolder와-Authentication)
* [AuthenticationManager와 Authentication](#AuthenticationManager와-Authentication)
* [ThreadLocal](#ThreadLocal)
* [Authentication과 SecurityContextHodler](#Authentication과-SecurityContextHodler)
* [스프링 시큐리티 필터와 FilterChainProxy](#스프링-시큐리티-필터와-FilterChainProxy)
* [DelegatingFilterProxy와 FilterChainProxy](#DelegatingFilterProxy와-FilterChainProxy)
* [AccessDecisionManager 1부](#AccessDecisionManager-1부)
* [AccessDecisionManager 2부](#AccessDecisionManager-2부)
* [FilterSecurityInterceptor](#FilterSecurityInterceptor)
* [ExceptionTranslationFilter](#ExceptionTranslationFilter)
* [스프링 시큐리티 아키텍처 정리](#스프링-시큐리티-아키텍처-정리)

## [섹션 2. 웹 애플리케이션 시큐리티](#섹션-2.-웹-애플리케이션-시큐리티)
* [스프링 시큐리티 ignoring() 1부](#스프링-시큐리티-ignoring()-1부)
* [스프링 시큐리티 ignoring() 2부](#스프링-시큐리티-ignoring()-2부)
* [Async 웹 MVC를 지원하는 필터: WebAsyncManagerIntegrationFilter](#Async-웹-MVC를-지원하는-필터:-WebAsyncManagerIntegrationFilter)
* [스프링 시큐리티와 @Async](#스프링-시큐리티와-@Async)
* [SecurityContext 영속화 필터: SecurityContextPersistenceFilter](#SecurityContext-영속화-필터:-SecurityContextPersistenceFilter)
* [시큐리티 관련 헤더 추가하는 필터: HeaderWriterFilter](#시큐리티-관련-헤더-추가하는-필터:-HeaderWriterFilter)
* [CSRF 어택 방지 필터: CsrfFilter](#CSRF-어택-방지-필터:-CsrfFilter)
* [CSRF 토큰 사용 예제](#CSRF-토큰-사용-예제)
* [로그아웃 처리 필터: LogoutFilter](#로그아웃-처리-필터:-LogoutFilter)
* [폼 인증 처리 필터: UsernamePasswordAuthenticationFilter](#폼-인증-처리-필터:-UsernamePasswordAuthenticationFilter)
* [로그인/로그아웃 폼 페이지 생성해주는 필터: DefaultLogin/LogoutPageGeneratingFilter](#로그인/로그아웃-폼-페이지-생성해주는-필터:-DefaultLogin/LogoutPageGeneratingFilter)
* [로그인/로그아웃 폼 커스터마이징](#로그인/로그아웃-폼-커스터마이징)
* [Basic 인증 처리 필터: BasicAuthenticationFilter](#Basic-인증-처리-필터:-BasicAuthenticationFilter)
* [요청 캐시 필터: RequestCacheAwareFilter](#요청-캐시-필터:-RequestCacheAwareFilter)
* [시큐리티 관련 서블릿 스팩 구현 필터: SecurityContextHolderAwareRequestFilter](#시큐리티-관련-서블릿-스팩-구현-필터:-SecurityContextHolderAwareRequestFilter)
* [익명 인증 필터: AnonymousAuthenticationFilter](#익명-인증-필터:-AnonymousAuthenticationFilter)
* [세션 관리 필터: SessionManagementFilter](#세션-관리-필터:-SessionManagementFilter)
* [인증/인가 예외 처리 필터: ExceptionTranslationFilter](#인증/인가-예외-처리-필터:-ExceptionTranslationFilter)
* [인가 처리 필터: FilterSecurityInterceptor](#인가-처리-필터:-FilterSecurityInterceptor)
* [토큰 기반 인증 필터 : RememberMeAuthenticationFilter](#토큰-기반-인증-필터-:-RememberMeAuthenticationFilter)
* [커스텀 필터 추가하기](#커스텀-필터-추가하기)

## [섹션 3. 스프링 시큐리티 그밖에](#섹션-3.-스프링-시큐리티-그밖에)
* [타임리프 스프링 시큐리티 확장팩](#타임리프-스프링-시큐리티-확장팩)
* [sec 네임스페이스](#sec-네임스페이스)
* [메소드 시큐리티](#메소드-시큐리티)
* [@AuthenticationPrincipal](#@AuthenticationPrincipal)
* [스프링 데이터 연동](#스프링-데이터-연동)
* [스프링 시큐리티 마무리](#스프링-시큐리티-마무리)
* [ 함께 학습하면 좋은 로드맵](#-함께-학습하면-좋은-로드맵)

## 섹션 0. 스프링 시큐리티: 폼 인증

### 강좌 자료

### 폼 인증 예제 살펴보기

### 스프링 웹 프로젝트 만들기

### 스프링 시큐리티 연동

### 스프링 시큐리티 설정하기

### 스프링 시큐리티 커스터마이징: 인메모리 유저 추가

### 스프링 시큐리티 커스터마이징: JPA 연동

### 스프링 시큐리티 커스터마이징: PasswordEncoder

### 스프링 시큐리티 테스트 1부

### 스프링 시큐리티 테스트 2부

## 섹션 1. 스프링 시큐리티: 아키텍처

### SecurityContextHolder와 Authentication

### AuthenticationManager와 Authentication

### ThreadLocal

### Authentication과 SecurityContextHodler

### 스프링 시큐리티 필터와 FilterChainProxy

### DelegatingFilterProxy와 FilterChainProxy

### AccessDecisionManager 1부

### AccessDecisionManager 2부

### FilterSecurityInterceptor

### ExceptionTranslationFilter

### 스프링 시큐리티 아키텍처 정리

## 섹션 2. 웹 애플리케이션 시큐리티

### 스프링 시큐리티 ignoring() 1부

### 스프링 시큐리티 ignoring() 2부

### Async 웹 MVC를 지원하는 필터: WebAsyncManagerIntegrationFilter

### 스프링 시큐리티와 @Async

### SecurityContext 영속화 필터: SecurityContextPersistenceFilter

### 시큐리티 관련 헤더 추가하는 필터: HeaderWriterFilter

### CSRF 어택 방지 필터: CsrfFilter

### CSRF 토큰 사용 예제

### 로그아웃 처리 필터: LogoutFilter

### 폼 인증 처리 필터: UsernamePasswordAuthenticationFilter

### 로그인/로그아웃 폼 페이지 생성해주는 필터: DefaultLogin/LogoutPageGeneratingFilter

### 로그인/로그아웃 폼 커스터마이징

### Basic 인증 처리 필터: BasicAuthenticationFilter

### 요청 캐시 필터: RequestCacheAwareFilter

### 시큐리티 관련 서블릿 스팩 구현 필터: SecurityContextHolderAwareRequestFilter

### 익명 인증 필터: AnonymousAuthenticationFilter

### 세션 관리 필터: SessionManagementFilter

### 인증/인가 예외 처리 필터: ExceptionTranslationFilter

### 인가 처리 필터: FilterSecurityInterceptor

### 토큰 기반 인증 필터 : RememberMeAuthenticationFilter

### 커스텀 필터 추가하기

## 섹션 3. 스프링 시큐리티 그밖에

### 타임리프 스프링 시큐리티 확장팩

### sec 네임스페이스

### 메소드 시큐리티

### @AuthenticationPrincipal

### 스프링 데이터 연동

### 스프링 시큐리티 마무리
