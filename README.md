# Spring Security Study Repository
> 인프런 스프링 시큐리티 강좌를(백기선님) 학습하고 정리한 내용입니다.

## [섹션 0. 스프링 시큐리티: 폼 인증](#섹션-0.-스프링-시큐리티:-폼-인증)
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

### 스프링 시큐리티 연동

* 스프링 부트 환경에서 스프링 시큐리티 추가 방법 (maven)
    * ```maven
      <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
      ```


#### 스프링 시큐리티의 의존성 추가 시 일어나는 일들
* 서버가 기동되면 스프링 시큐리티의 초기화 작업 및 보안 설정이 이루어진다
* 별도의 설정이나 구현을 하지 않아도 기본적인 웹 보안 기능이 현재 시스템에 연동되어 작동함
    1. `모든 요청은 인증이 되어야 자원에 접근이 가능하다`
    2. 인증 방식은 `폼 로그인` 방식과 `httpBasic 로그인` 방식을 제공한다
    3. 기본 로그인 페이지 제공한다 (/login)
    4. 기본 계정 한 개 제공한다 – username : user / password : 랜덤 문자열


> Using generated security password: __40f5bd88-a7f3-4d6f-916d-bfd7f142b9f8__

스프링 시큐리티가 기본적으로 제공하는 `계정`의 패스워드. 로그인 할 때 사용

> ID: __user__  
> password __40f5bd88-a7f3-4d6f-916d-bfd7f142b9f8__


`http://localhost:8080/login` 로 접속시 다음과 같이 사용
![](img/2020-12-18-23-14-40.png)


<br>
<br>
![](img/2020-12-18-23-19-52.png)

---

### 스프링 시큐리티 설정하기

스프링 시큐리티를 설정할 때는, 보통 `WebSecurityConfigurerAdapter` 를 상속 받은 configure 클래스를 새로 작성 한다.
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
    }
}

```
* EnableWebSecurity : 웹 보안 활성 어노테이션
* 보통 WebSecurityConfigurerAdapter를 상속받은 메소드들을 오버라이딩 하는 방식으로 설정한다.
```java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        // ex) 루트로 오는 요청과 info로 오는 요청은 인증을 거치지 않아도 상관 없다는 설정
        http.authorizeRequests()
                .mvcMatchers("/", "/info").permitAll();
    }

```

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
