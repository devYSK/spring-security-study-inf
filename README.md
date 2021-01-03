# Spring Security Study Repository
> 인프런 스프링 시큐리티 강좌를(백기선님) 학습하고 정리한 내용입니다.

# [섹션 0. 스프링 시큐리티: 폼 인증](#섹션-0.-스프링-시큐리티:-폼-인증)
* [스프링 웹 프로젝트 만들기](#스프링-웹-프로젝트-만들기)
* [스프링 시큐리티 연동](#스프링-시큐리티-연동)
* [스프링 시큐리티 설정하기](#스프링-시큐리티-설정하기)
* [스프링 시큐리티 커스터마이징: 인메모리 유저 추가](#스프링-시큐리티-커스터마이징:-인메모리-유저-추가)
* [스프링 시큐리티 커스터마이징: JPA 연동](#스프링-시큐리티-커스터마이징:-JPA-연동)
* [스프링 시큐리티 커스터마이징: PasswordEncoder](#스프링-시큐리티-커스터마이징:-PasswordEncoder)
* [스프링 시큐리티 테스트 1부](#스프링-시큐리티-테스트-1부)
* [스프링 시큐리티 테스트 2부](#스프링-시큐리티-테스트-2부)

# [섹션 1. 스프링 시큐리티: 아키텍처](#섹션-1.-스프링-시큐리티:-아키텍처)
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

# [섹션 2. 웹 애플리케이션 시큐리티](#섹션-2.-웹-애플리케이션-시큐리티)
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

# [섹션 3. 스프링 시큐리티 그밖에](#섹션-3.-스프링-시큐리티-그밖에)
* [타임리프 스프링 시큐리티 확장팩](#타임리프-스프링-시큐리티-확장팩)
* [sec 네임스페이스](#sec-네임스페이스)
* [메소드 시큐리티](#메소드-시큐리티)
* [@AuthenticationPrincipal](#@AuthenticationPrincipal)
* [스프링 데이터 연동](#스프링-데이터-연동)
* [스프링 시큐리티 마무리](#스프링-시큐리티-마무리)
* [ 함께 학습하면 좋은 로드맵](#-함께-학습하면-좋은-로드맵)

# 섹션 0. 스프링 시큐리티: 폼 인증

## 스프링 시큐리티 연동

* 스프링 부트 환경에서 스프링 시큐리티 추가 방법 (maven)
    * ```maven
      <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
      ```


# 스프링 시큐리티의 의존성 추가 시 일어나는 일들
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

## 스프링 시큐리티 설정하기

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

* anyRequest() : 기타 등등한 요청에 대하여 설정 
* formLogin() : 폼 로그인을 사용할 것이다
* and() : 메서드 체이닝을 이용해서 연속으로 설정
  
## 스프링 시큐리티 커스터마이징: 인메모리 유저 추가

* `UserDetailsServiceAutoConfiguration` 클래스
  * 이 클래스를 열어보면 우리가 어떻게 커스텀 할지 힌트를 얻을 수 있다.
  * `inMemoryUserDetailsManager()` 메소드에서 `SecurityProperties`객체를 인자로 받는다
  * `SecurityProperties` 클래스안에 `User` 클래스가 있고, 이 클래스가 기본적인 인증을 위해 필요한 변수 등을 보여주는 틀이다. 

* application.properties 파일에서 기본으로 제공되는 아이디의 유저명, 패스워드, 권한을 설정할 수 있다.
  * ```properties
    spring.security.user.name=admin
    spring.security.user.password=123
    spring.security.user.roles=ADMIN
    ```  
  
  * 설정 하게 되면 자동으로 설정되는 password를 쓰지 않기 때문에 콘솔에 비밀번호가 출력이 되지 않는다. 
  * 안전하지 않고 권장하지 않는다. 

* `AuthenticationManagerBuilder`를 인자로 받는 `configure` 메서드 
  * 이것을 사용하면 우리가 원하는 유저를 만들어서 인메모리 방식으로 설정할 수 있다. 

```java
// WebSecurityConfigurerAdapter를 상속받은 SpringSecurity 클래스 내 `메서드 `

@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("youngsoo").password("{noop}123").roles("USER").and()
                .withUser("keesun").password("{noop}123").roles("USER").and()
                .withUser("admin").password("{noop}!@#").roles("ADMIN");
    }

```
* {} : 패스워드 앞에 붙여 사용하는 패스워드 인코더. 
* {noop} : noop은 암호화를 하지 않았다는것.
  * [참고!!](https://java.ihoney.pe.kr/498)  
  * PasswordEncoderFactories클래스의 
  * createDelegatingPasswordEncoder에 정의되어 있는 PasswordEncoder 종류를 보자 
  * 
## 스프링 시큐리티 커스터마이징: JPA 연동

* JPA 의존성 추가
```MAVEN
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
```
* h2 추가 
```
<dependency>
    <groupId>com.h2database</groupId>
    <artifactId>h2</artifactId>
</dependency>
```

```java
@Service
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {

    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        Account account = accountRepository.findByUsername(s);

        if (account == null) {
            throw new UsernameNotFoundException(s);
        }

        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

}
```

* UserDetailService 인터페이스
  * DAO를 가지고 와서 유저 정보를 인증하는데 쓰인다 
  * username을 으로 해당하는 정보를 가져와서 UserDetails로 리턴하는것.   
  * 스프링 시큐리티의 `User` 클래스의 Builder를 이용해서 UserDetails를 만들 수 있다. 


# UserDetailService에 인증 정보 등록하는법 
## 명시적으로 Security Config에 정의하는법

* 1. UserDetailsService를 구현한 Service클래스를 정의
```java
@Service
@RequiredArgsConstructor
public class AccountService implements UserDetailsService {

    private final AccountRepository accountRepository;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        Account account = accountRepository.findByUsername(s);

        if (account == null) {
            throw new UsernameNotFoundException(s);
        }

        return User.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }
    ... 생략
}
```

* 2. Security Config의 AuthenticationManagerBuilder 인자를 받는 configure 메소드에서 서비스를 등록
```java

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AccountService accountService;

    ... 생략

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService);

    }
}

```

> 명시적으로 AuthenticationManagerBuilder에 등록하지 않아도  
> UserDetailsService 타입의 Bean으로 등록만 되있으면 알아서 가져다 쓴다.  
> PasswordEncorder도 마찬가지. 

<br>

## 스프링 시큐리티 커스터마이징: PasswordEncoder

> # 비밀번호는 평문이 아닌 단방향 알고리즘으로 인코딩해서 저장해야 한다

회원가입을 하는 과정에 패스워드를 암호화 하는데  

보통 `PasswordEncoder`를 Bean으로 등록하고 서비스나 도메인 계층에서 비밀번호를 암호화 한다.

* 스프링 시큐리티5에서 권장하는 PassowrdEncoder
* PasswordEncoderFactories.createDelegatingPasswordEncoder()
 
* 다양한 패스워드 인코딩을 지원한다. 
  
* # Password Encoder 종류
    * BCryptPasswordEncoder
    * NoOpPasswordEncoder
    * Pbkdf2PasswordEncoder
    * ScryptPasswordEncoder
    * StandardPasswordEncoder
 
```java
 @Bean
 public PasswordEncoder passwordEncoder() {
     return PasswordEncoderFactories createDelegatingPasswordEncoder();
 }
```

## 스프링 시큐리티 테스트 1부

## `이 강좌에서는 JUnit4 기반으로 테스트를 작성!!!`

* https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#test-mockmvc

* Spring-Security-Test 의존성 추가
  ```java
  <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-test</artifactId>
    <scope>test</scope>
  </dependency>
  ```
  *  테스트에서 사용할 기능을 제공하기 때문에 Test 스콥이 적절

@AutoConfigureMockMvc 를 사용하면 MockMvc 테스트를 진행할 수 있다

```java
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class SpringBootTest {
    @Test
    public void index_user() throws Exception {
        mockMvc.perform(get("/")
                .with(user("youngsoo").roles("USER")))// 이러한 가짜 유저가 있다 하고 요청을 보내는것
                .andDo(print())
                .andExpect(status().isOk());

    }
}
```
* with(user("name").roles("USER)) 
  * 가짜 유저를 mocking 하여 요청을 한다.  
```java
 @Test
public void admin_user() throws Exception {
    mockMvc.perform(get("/admin")
            .with(user("youngsoo").roles("USER")))// 이러한 가짜 유저가 있다 하고 요청을 보내는것
            .andDo(print())
            .andExpect(status().isForbidden());
}
```
* USER 권한을 가진 유저가 admin에 접근하면 foridden 응답이 온다.
  
<br>

## 어나니머스 유저가 접근할 때 사용하는 어노테이션 `@WithAnonymousUser`

```java
@Test
@WithAnonymousUser
public void index_anonymous() throws Exception {
    mockMvc.perform(get("/"))
            .andDo(print())
            .andExpect(status().isOk());
}
```
<br>

## 유저를 직접 설정(Mocking)하여 유저 접근
```java
@Test
@WithMockUser(username = "youngsoo", roles = "USER")
public void index_user_youngsoo() throws Exception {
    mockMvc.perform(get("/"))
            .andDo(print())
            .andExpect(status().isOk());
}
```
* `@WithMockUser()` 어노테이션 
    * username, roles, authorities, password 등 설정 가능 

## 직접 어노테이션을 커스텀 할 수도 있다.

```java
@Retention(RetentionPolicy.RUNTIME)
@WithMockUser(username = "youngsoo", roles = "USER")
public @interface WithUser {
}
```

> 다음과 같이 사용할 수 있다. 
```java
@Test
@WithUser // <<<
public void index_user_youngsoo() throws Exception {
... 
}
```
---
# 스프링 시큐리티 테스트 2부

# 폼 로그인 테스트 방법
```java
@Transactional
@Test
public void login() throws Exception {
    String username = "youngsoo";
    String password = "123";
    
    Account user = createUser(username, password);
    mockMvc.perform(formLogin().user(user.getUsername()).password(password))
            .andExpect(authenticated());
}

private Account createUser(String username, String password) {
    Account account = new Account();
    account.setUsername(username);
    account.setPassword(password);
    account.setRole("USER");
    return accountService.createNew(account);
}

```

* 레포지토리에 Account를 생성하고 formLogin() 메서드를 이용하여 인증하면  
  authenticated()로 인증 결과를 알 수 있다. 

* 인증에 실패하는걸 확인하려면 `unauthenticated()`를 이용하면 된다. 

---

# 섹션 1. 스프링 시큐리티: 아키텍처
![](img/2020-12-31-21-16-11.png)
1. 웹으로부터 요청이 들어오면 서블릿 필터 중 DeligatingFilterProxy 를 통해 들어온다.

  (DeligatingFilterProxy 는 스프링부트를 사용할 때 자동적으로 등록된다)

2. 1번에서 특정한 Bean (SpringSecurityFilterChain) 에 필터 기능을 위임하여 스프링 시큐리티에

   내장된 15가지 필터들을 사용하게 된다. (FilterChainProxy 를 통해)

3. 2번의 체인의 필터들은 WebScurity, HttpSecurity 를 사용하면서 만들어진다.
   WebSecurityConfigurerAdater 를 상속하는 SecurityConfig 파일에서 우리 프로젝트에 맞는

   security 설정을 해주면 내장된 필터들에 설정들이 자동적으로 반영된다.


--- 
> # Authentication (인증)
> # Authorization (인가)

## SecurityContextHolder와 Authentication
https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#core-components


* ## SecurityContextHolder
  - SecurityContext 제공, 기본적으로 ThreadLocal을 사용한다.
  - ThreadLocal : 한 쓰레드 내에서 share 하는 저장소
  - 
* ## SecurityContext
  - Authentication 제공.  

> 우리가 어떤 애플리케이션에서 인증을 거치고 나면 그 인증된 사용자 정보를 Principal 이라고 하는데,  
> 이 Principal 정보를 Authentication 이라는 객체에 `담아서` 관리를 하고,  
> Authentication는 SecurityContext에, SecurityContext는 SecurityContextHolder로 감싸져 있다. 

## 범위 : `SecurityContextHolder(SecurityContext[Authentication])`

<img src = "img/2020-12-31-21-19-25.png" width ="250" height="250">

## Authentication -(인증 객체)
- `Principal`과 `GrantAuthority` 제공.
- SecurityContextHolder.getContext().getAuthentication(); 로 꺼낼 수 있다

## Principal - (누구 객체 )
- “누구"에 해당하는 정보.
- 객체는 `UserDetails 타입`. 
  - authentication.getPrincipal() 메서드로 꺼내면 `Object` 타입이지만,  
    사실은 `UserDetails`, `User` 타입이다.  
- authentication.getPrincipal()로 꺼낼 수 있다.
- UserDetailsService를 구현한 서비스에서 리턴한 객체

```java
@Service
public class AccountService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        //.... 생략
    }
}

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired AccountService accountService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(accountService); // << 여기서 리턴한 객체 
    }
}
```

## GrantAuthority - (권한 객체)
- “ROLE_USER”, “ROLE_ADMIN”등 Principal이 가지고 있는 “권한”을 나타낸다.
- 인증 이후, 인가 및 권한 확인할 때 이 정보를 참조한다.
- 권한은 여러가지를 가질 수 있다.

## UserDetails 
- 애플리케이션이 가지고 있는 유저 정보와 스프링 시큐리티가 사용하는 Authentication 객체 사이의 어댑터.

## UserDetailsService
- 유저 정보를 UserDetails 타입으로 가져오는 DAO (Data Access Object) 인터페이스.
- 유저 정보를 UserDetails 타입으로 가져오는 DAO (Data Access Object) 인터페이스.

* ##  폼을 통하여 로그인 할때 들어오는 정보를 디버그 하면 다음과 같다

```
// authentication 객체
authentication = "UsernamePasswordAuthenticationToken" 
 - Principal= org.springframework.security.core.userdetails.User 
 - credentials = null
 - authorities = {Collections$UnmodifiableRandomAccessList@10828}  size = 1
 - details = {WebAuthenticationDetails@10833} 
 - authenticated = true

// principal 객체 
principal ="org.springframework.security.core.userdetails.User" 
 - password = null
 - username = "youngsoo"
 - authorities = {Collections$UnmodifiableSet@10854}  size = 1
 - accountNonExpired = true
 - accountNonLocked = true
 - credentialsNonExpired = true
 - enabled = true
 
// authroites
authorities = {Collections$UnmodifiableRandomAccessList@10713}  size = 1
 - 0 = {SimpleGrantedAuthority@10871} "ROLE_USER"
 - role = "ROLE_USER"
```

> 객체 이름은 = , 멤버 필드는 -

--- 

## AuthenticationManager와 Authentication
### 스프링 시큐리티에서 인증(Authentication)은 `AuthenticationManager`가 한다
- ` AuthenticationManager가 Authentication 객체를 만들고 인증을 처리한다.`
  
- AuthenticationManager : 인터페이스 
- AuthenticationManager는 authenticate 메서드 하나밖에 없다.

> Authentication authenticate(Authentication authentication) throws AuthenticationException;

* 인자로 받은 Authentication​이 `​유효한 인증인지 확인​`하고 `​Authentication 객체를 리턴​`한다.
 
* 인증을 확인하는 과정에서 비활성 계정, 잘못된 비번, 잠긴 계정 등의 에러를 던질 수 있다

- AuthenticationManager 인터페이스를 구현하는 객체 
  - ProviderManager
  - 또는 AuthenticationManager 구현
  - AuthenticationManager 직접 구현할 필요는 없지만,  
    ProviderManager 클래스를 보면서 어떻게 인증이 이루어지는지 알 수 있다.

<br>

## > 인자로 받은 Authentication
* 사용자가 입력한 인증에 필요한 정보(username, password)로 만든 객체. (폼 인증인 경우)

* Authentication
    * Principal: “keesun”
    * Credentials: “123”
## > 유효한 인증인지 확인

* 사용자가 입력한 password가 UserDetailsService를 통해 읽어온 UserDetails 객체에 들어있는 password와 일치하는지 확인

* 해당 사용자 계정이 잠겨 있진 않은지, 비활성 계정은 아닌지 등 확인

## > Authentication 객체를 리턴
* Authentication
    * Principal: UserDetailsService에서 리턴한 그 객체 (User)
    * Credentials:
    * GrantedAuthorities

## > 폼 로그인을 한다면, 인증이 일어나는 순서

-> AuthenticationManager를 구현한 ProviderManager가 인증 수행

1. ProviderManager.authenticate(Authentication `authentication`) 메소드 내에서 인증 수행 
   *  인자로 받은 authentication은 우리가 폼에서 입력한 정보   
      (UsernamePasswordAuthenticationToken)

2.  authentication 인증 객체는 Provider가 처리하는데, 
    ProviderManager가 가진 `List<AuthenticationProvider> providers` 중에  
    현재 인증 객체를 처리 할 수 있는 Provider가 없으면 parent로 간다.  
    (다른 Provider가 처리할 수 있게, 링크드 리스트 처럼 연결)
    ```java
    if (result == null && this.parent != null) {        
        result = this.parent.authenticate(authentication);
    ```
3. parent Provider에서 다시 인증 할 수 있는지 확인한다. (다른 Provider 클래스)
4. 다른 Provider가 인증을 처리 할 수 있다면, UserDetails서비스를 사용해서 인증한다.  
   * AbstractUserDetailsAuthenticationProvider.authenticate() 메서드 

5. 캐시된 유저가 있나 등을 확인하고, retrieveUser() 메서드를 호출하여 Provider 안으로 들어간다.(예제는 DaoAuthenticationProvider)
6. 이 Provider의 `protected final UserDetails retrieveUser` 메소드에서   
   사용하는 UserDetailsService가 우리가 만든 UserDetailsService를 구현한 AccountService 이다 
```java
// DaoAuthenticationProvider 클래스의 retrieveUser 메서드
 protected final UserDetails retrieveUser(String username, 
                                          UsernamePasswordAuthenticationToken authentication) 
                                          throws AuthenticationException {
    this.prepareTimingAttackProtection();
    try {
        UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username); // <<<<
        if (loadedUser == null) {
            throw new InternalAuthenticationServiceException("UserDetailsService returned null, 
                                                             which is an interface contract violation");
        } else {
            return loadedUser;
        }
    }
}
```

7. 이후 추가적인 체크를 한다 (계정이 lock인지 등)
8. 무사히 다 통과한다면 result 라는 `authentication 객체`를 리턴하는데,  
   이 `authentication 객체`가 우리가 UserDetailsService를 구현한 구현체인  
   AccountService에서 loadUserByUsername 메서드의 리턴값인 `UserDetails`이다. 
   *  이 `UserDetails` 객체 가 Authencation 안에 들어가는 `principal`객체이다

> ProviderManager의 authenticate 메서드에서 리턴한 result 객체가 인증이 되면,   
> principal이 되어 authentication 객체가 되고  
> SecurityContextHolder.getContext().getAuthentication 으로 꺼낼 수 있게 된다.   

---
## ThreadLocal

Java.lang 패키지에서 제공하는 쓰레드 범위 변수. 즉, 쓰레드 수준의 데이터 저장소.
* 같은 쓰레드 내에서만 공유.

* 따라서 같은 쓰레드라면 해당 데이터를 메소드 매개변수로 넘겨줄 필요 없이 get으로 꺼낼 수 있따. 
  
* `SecurityContextHolder의 기본 전략.`
    * SecurityContext를 ThreadLocal에 갖고 있어서 공유가 가능하다. 

```java
public class AccountContext {
    private static final ThreadLocal<Account> ACCOUNT_THREAD_LOCAL = new ThreadLocal<>();

    public static void setAccount(Account account) {
        ACCOUNT_THREAD_LOCAL.set(account);
    }
    public static Account getAccount() {
        return ACCOUNT_THREAD_LOCAL.get();
    }
}
```

AccountContext.getAccount()로 어디서든 꺼낼 수 있다. 

---

## Authentication과 SecurityContextHodler

AuthenticationManager가 인증을 마친 뒤 리턴 받은 Authentication 객체의 행방은??

-> SecurityContextHolder에 들어가서 애플리케이션 전반에 사용할 수 있게 된다. 

`UsernamePasswordAuthenticationFilter` 와   
`SecurityContextPersisenceFilter` 가  
Authentication을 SecurityContextHold에 넣어준다. 


### UsernamePasswordAuthenticationFilter
* 폼 인증을 처리하는 시큐리티 필터
 
* AuthenticationManager를 이용해서 인증한다. 
* 인증된 Authentication 객체를 SecurityContextHolder에 넣어주는 필터
  
* SecurityContextHolder.getContext().setAuthentication(authentication)


### SecurityContextPersisenceFilter
* SecurityContext를 HTTP session에 캐시(기본 전략)하여 여러 요청에서 Authentication을 공유하는 필터.

* SecurityContextRepository를 교체하여 세션을 HTTP session이 아닌 다른 곳에 저장하는
것도 가능하다.
  * HttpSession이 날라가면 저장되었떤 인증 정보도 날라간다. 

AuthenticationManager를 사용하는 부분은 UsernamePasswordAuthenticationFilter이다.
UsernamePasswordAuthenticationFilter에서 Authentication 객체를  SecurityContextHolder에 넣는다. 

UsernamePasswordAuthenticationFilter에서 인증이 이루어지고   
SecurityContextHolder에 authentication이 저장이 되고 SecurityContextPersitenceFilter에서 Http session에 authentictication을 캐시한다

---

## 스프링 시큐리티 필터와 FilterChainProxy

* FilterChainProxy는 요청(HttpServletRequest)에 따라 적합한 SecurityFilterChain을 사용
* 기본 전략으로 DefaultSecurityFilterChain을 사용
* DefaultSecurityFilterChain는 Filter 리스트를 가지고 있다
* SecurityFilterChain을 여러개 만들고 싶으면 SecurityConfig 클래스를 여러개 만든다
* 이 때 SecurityConfig가 상충할 수 있으니 Order 어노테이션을 통해 우선순위를 지정한다
* Filter 개수는 SecurityConfig 설정에 따라 달라진다
* FilterChainProxy는 필터를 호출하고 실행한다



* 스프링 시큐리티가 제공하는 필터들 - 클릭해서 조회
  1. [WebAsyncManagerIntegrationFilter](#Async-웹-MVC를-지원하는-필터:-WebAsyncManagerIntegrationFilter)
  2. [`SecurityContextPersistenceFilter`](#SecurityContext-영속화-필터:-SecurityContextPersistenceFilter) < 
  3. [HeaderWriterFilter](#시큐리티-관련-헤더-추가하는-필터:-HeaderWriterFilter)
  4. [CsrfFilter](#CSRF-어택-방지-필터:-CsrfFilter)
  5. [LogoutFilter](#로그아웃-처리-필터:-LogoutFilter)
  6. [`UsernamePasswordAuthenticationFilter`](#폼-인증-처리-필터:-UsernamePasswordAuthenticationFilter) <
  7. [DefaultLoginPageGeneratingFilter](#로그인/로그아웃-폼-페이지-생성해주는-필터:-DefaultLogin/LogoutPageGeneratingFilter)
  8. [DefaultLogoutPageGeneratingFilter](#로그인/로그아웃-폼-페이지-생성해주는-필터:-DefaultLogin/LogoutPageGeneratingFilter)
  9. [BasicAuthenticationFilter](#Basic-인증-처리-필터:-BasicAuthenticationFilter)
  10. [RequestCacheAwareFilter](#요청-캐시-필터:-RequestCacheAwareFilter)
  11. [SecurityContextHolderAwareRequestFilter](#시큐리티-관련-서블릿-스팩-구현-필터:-SecurityContextHolderAwareRequestFilter)
  12. [AnonymousAuthenticationFilter](#익명-인증-필터:-AnonymousAuthenticationFilter)
  13. [SessionManagementFilter](#세션-관리-필터:-SessionManagementFilter)
  14. [ExceptionTranslationFilter](#ExceptionTranslationFilter)
  15. [FilterSecurityInterceptor](#FilterSecurityInterceptor)

이 모든 필터는 ​FilterChainProxy​클래스가 호출한다.

![](img/2021-01-01-21-38-02.png)

* 필터 목록에 있는 필터들을 순서대로 실행(호출)한다. 

* 필터 목록을 선택할 때 SeicurityFilterChain이라는 목록에서 선택한다. 


이 목록들이 만들어지고, 커스터마이징 되는 지점이 SecurityConfig 이다

SecurityConfig의 config에서 SecurityFilterChain을 만든다 

```java
public class FilterChainProxy extends GenericFilterBean {
   ... 생략
   private List<Filter> getFilters(HttpServletRequest request) { // filter 목록 가져오기
    for (SecurityFilterChain chain : filterChains) {
        if (chain.matches(request)) {
            return chain.getFilters();
        }
    }
    return null;
    } 
   ... 생략
}
```
* filter의 목록을 가져오는 getFilters()

* filter 목록의 구성은 public class SecurityConfig extends 
  WebSecurityConfigurerAdapter

* a. WebSecurityConfigurerAdapter 상속 객체가 여럿일 때 @Order어노테이션으로 순서를 정한다  
  * 여러 SecurityConfig 클래스가 있을 때 어떤 설정 클래스가 먼저일지 정하는것. 


* b. http.antMatcher()

## DelegatingFilterProxy와 FilterChainProxy

* filter : 앞뒤로 특정한일들을 할 수 있는 어떤 요청을 처리하는 필터 클래스들. 

DelegatingFilterProxy
* DelegatingFilterProxy는 스프링 시큐리티가 모든 애플리케이션 요청을 감싸게 해서 모든 요청에 보안이 적용되게 하는 서블릿필터
  
* 일반적인 서블릿 필터.
* 서블릿 필터 처리를 스프링에 들어있는 빈으로 위임하고 싶을 때 사용하는 서블릿 필터.
  * ### 자기가 직접 처리하는게 아니고 다른 필터에게 자기가 해야 할 일을 위임한다.
 
* 타겟 빈 이름을 설정한다.
* 스프링 부트 없이 스프링 시큐리티 설정할 때는  
  `AbstractSecurityWebApplicationInitializer`를 사용해서 등록.

* 스프링 부트를 사용할 때는 자동으로 등록 된다. (SecurityFilterAutoConfiguration)
 
FilterChainProxy

* 보통 “springSecurityFilterChain” 이라는 이름의 빈으로 등록된다

![](img/2021-01-02-13-26-33.png)
* [DelegatingFilterProxy가 FilterChainProxy에게 작업을 위임한다.](#자기가-직접-처리하는게-아니고-다른-필터에게-자기가-해야-할-일을-위임한다.)
   
* 서블릿 컨테이너에는 DelegatingFilterProxy `하나`만 등록되어있고 filter 호출 시 applicationContext내 `filterChainProxy를 호출`해서 security처리를 한다.

--- 

## AccessDecisionManager 1부
AccessControl 또는 Authorization 라고 부른다

이미 인증을 거친 사용자가 특정한 서버에 리소스에 접근을 할 때,  
그게 웹 요청이든 메소드 call 이든 그 것을 허용할 것인가?  
유효한 요청인가를 판단하는 인터페이스. - `인가`를 하는 인터페이스

Access Control 결정을 내리는 인터페이스로, 기본 구현체 3가지를 제공한다.
### Access Control 확인 전략
* AffirmativeBased​: 여러 Voter(투표자)중에 한명이라도 허용하면 허용. 기본 전략.

* ConsensusBased: 다수결

* UnanimousBased: 만장일치

AccessDecisionVoter
* 해당 Authentication이 특정한 Object에 접근할 때 필요한 ConfigAttributes를 만족하는지 확인한다.
* WebExpressionVoter​: 웹 시큐리티에서 사용하는 기본 구현체, ROLE_Xxxx가
매치하는지 확인. (USER, ADMIN 등등)
* RoleHierarchyVoter: 계층형 ROLE 지원. ADMIN > MANAGER > USER
* ...
---

## AccessDecisionManager 2부
AccessDecisionManager 또는 Voter를 커스터마이징 하는 방법

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
   public SecurityExpressionHandler expressionHandler() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        // 어드민은 유저보다 상위니 유저가 할 수 있는건 어드민도 할 수 있다.
        DefaultWebSecurityExpressionHandler handler = new
                DefaultWebSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        return handler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                .expressionHandler(expressionHandler()); // <<
        http.formLogin();
        http.httpBasic();
    }    
    ....
}
```
RoleHierarchyImpl로 계층 권한을 구현하고 
시큐리티 익스프레션 핸들러를 설정한다. 

--- 

## FilterSecurityInterceptor

* AccessDecisionManager를 사용하여 Access Control 또는 예외 처리 하는 필터.  
대부분의 경우 FilterChainProxy에 제일 마지막 필터로 들어있다

* 인증이 된 상태에서 특정 리소스에 접근할 수 있는지 Role을 확인함

![](img/2021-01-02-15-36-09.png)

- 인증이 된 상태에서 최종적으로 마지막에 검토하는 필터 

--- 

## ExceptionTranslationFilter
필터 체인에서 발생하는 AccessDeniedException과 AuthenticationException을 처리하는 필터

AuthenticationException(인증 예외, 권한이 요구되는 페이지에 권한없이 접근할 때) 발생 시 

* AuthenticationEntryPoint 실행
  
* AbstractSecurityInterceptor 하위 클래스(예, FilterSecurityInterceptor)에서 발생하는 예외만 처리.

* 그렇다면 UsernamePasswordAuthenticationFilter에서 발생한 인증 에러는?

AccessDeniedException 발생 시

* 익명 사용자라면 > AuthenticationEntryPoint 실행 (로그인 페이지로 이동)

* 익명 사용자가 아니면 >  AccessDeniedHandler에게 위임

---

# 스프링 시큐리티 아키텍처 정리
![](img/2021-01-02-16-39-16.png)

서블릿 컨테이너에 요청이 들어오면, DeligatingFilterProxy가  
WebSecurity를 가지고 FilterChainProxy를 만들어 필터 처리를 위임한다.

인증에 관해서는 AuthenticationManager를 사용하고,  
인가(Access Control)에 관해서는 AccessDecisionManager를 사용한다. 

인증에 관해서는 AuthenticationManager의 구현체로 ProviderManager를 사용
* ProviderManager는 다른 여러 AuthenticationProvider를 이용해서 인증을 처리
    * 그중에 DaoAuthenticationProvider를 사용

    * UserDetailsSerivce를 이용하여 읽어온 데이터에서 유저정보를 사용해서 인증을한다.


* 인증이 성공한다면 Authentication 정보를 SecurityContextHolder와 세션에  
  넣어놓고 APP 전반에 걸쳐 사용. 

세션에 저장된 Authentication 정보가 SecurityContextPersistenFilter에 의해 읽힘.

인증이 됬다면, 최종적으로 인가(Authorization)를 처리하는 FilterSecurityInterceptor 필터가 AccessDecisionManager를 사용해서 인가 처리를 한다.(Access Control) 
  * 현재 Authentication이 내가 접근하려는 리소으에(url, 메서드) 접근할 때 적절한 권한(Role)을 가지고 있는가 확인 
  * [권한 확인하는 전략](#Access-Control-확인-전략) 중 기본적으로 3가지 가 있는데 AffirmativeBased를 기본 전략으로 사용 
  
## <순서>

* ## 인증 (AuthenticationManager)
  * SecurityContextPersistenceFilter
    * AuthenticationManager
      * ProviderManager
        * DaoAuthenticationProvider
          * UserDetailService

* ## 인가(AccessDecisionManager)

  * FilterSecurityInterceptor
    * AccessDecisionManager
      * AffirmativeBased
        * WebExpressionVoter(AccessDecisionVoters)
          * SecurityExpressionHandler

참고
* https://spring.io/guides/topicals/spring-security-architecture
* https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#overall-architecture

--- 

# 섹션 2. 웹 애플리케이션 시큐리티
WebSecurity의 ignoring()을 사용해서 `시큐리티 필터 적용을 제외할 요청을 설정`할 수 있다. 


## 스프링 시큐리티 ignoring() 1부

* #### configure(WebSecurity web)
```java
@Override
public void configure(WebSecurity web) throws Exception {
    web.ignoring()
                .mvcMatchers("/favicon.ico"); // (1)번 
    web.ignoring()
       .requestMatchers(PathRequest.toStaticResources()
                                    .atCommonLocations());// (2)번
    }
```
* 정적 자원 요청 같은 것들도 다 여러개의 필터를 거치는데,  
   `1번` 처럼 설정하면 필터를 거치지 않아서 속도가 조금 더 빨라진다.    
  (당연히 저런 요청 하나 하나 다 필터 여러개를 거치면 속도가 느려진다.)


--- 

## 스프링 시큐리티 ignoring() 2부

## 그러나!
* 매번 스태틱 리소스들을 일일히 하나씩 다 적어두기 귀찮기 때문에 스프링 부트는 다음을 제공한다. -> `PathRequest` (2)
  
* 스프링 부트가 제공하는 PathRequest를 사용해서 `정적 자원 요청`을 스프링 시큐리티 필터를 적용하지 않도록 설정.

* `CommonLocations`은 5개의 자원에 대해 필터를 무시하도록 한다.
    ```java
    // StaticRespourceLocation.java (enum)
    public enum StaticResourceLocation {
        CSS(new String[]{"/css/**"}),
        JAVA_SCRIPT(new String[]{"/js/**"}),
        IMAGES(new String[]{"/images/**"}),
        WEB_JARS(new String[]{"/webjars/**"}),
        FAVICON(new String[]{"/favicon.*", "/*/icon-*"});
        ...
    }
    ```

* 이렇게도 사용 가능 하다. 결과는 같지만 `똑같지 않다.`
  * ```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .mvcMatchers("/", "/info", "/account/**").permitAll()
                .mvcMatchers("/admin").hasRole("ADMIN")
                .mvcMatchers("user").hasRole("USER")
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll();
    ```
* [`전자(configure(WebSecurity web))를 사용하자.!`](#configure(WebSecurity-web))  


* ignoring() 뒤에다가 어떤 메소드 체이닝을 걸든 거치는 필터 목록은 없어진다(0개가 된다)
    * 방법이 매우 다양하다. 

* web.ignoring()

    * .requestMatchers()

    [requestMatchers docs](#https://docs.spring.io/spring-security/site/docs/4.2.13.RELEASE/apidocs/org/springframework/security/config/annotation/web/builders/HttpSecurity.html#requestMatchers--)


    * .requestMatcher(RequestMatcher matcher)

    * .mvcMatchers(String mvcPatterns)

    * .antMatchers(String antPatterns)

    * .regexMatchers(String regexPatterns)

* PathRequest

  * org.springframework.boot.autoconfigure.security.servlet.PathRequest  
    Spring Boot가 제공하는 PathRequest를 사용해서 정적 지원 요청을 필터를 적용하지 않도록 설정.

* http.authorizeRequests() .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
  * 위의 web.ignoring()와 같은 결과이지만   
    security filter가 적용된다 차이가 있다. 

* 정적 / 동적 resource에 따른 처리방식.

  * 동적 resource는 http.authorizeRequests()로 처리하는 것을 권장.        
    configure(HttpSecurity http) 메서드
  
  * 정적 resource는 WebSecurity.ignore()를 권장하며 예외적인 정적 자원 (인증이 필요한 정적자원이 있는 경우)는 http.authorizeRequests()를 사용할 수 있다.

---

## Async 웹 MVC를 지원하는 필터: WebAsyncManagerIntegrationFilter

15개 정도의 시큐리티 필터들 중 가장 위에 (먼저) 있는 필터.

스프링 MVC의 Async 기능(핸들러에서 Callable을 리턴할 수 있는 기능)을 사용할 때에도 `SecurityContext를 공유`하도록 도와주는 필터.
  * 다른 쓰레드 간에 공유. 
      
* PreProcess: SecurityContext를 설정한다.

* Callable: 비록 다른 쓰레드지만 그 안에서는 동일한 SecurityContext를 참조할 수 있다.

* PostProcess: SecurityContext를 정리(clean up)한다.

---
## 스프링 시큐리티와 @Async

@Async를 사용한 서비스를 호출하는 경우

* @Async 사용한 서비스 호출 시  
  쓰레드가 다르기 때문에 (서비스는 하위 스레드를 생성)  
  따라서 SecurityContext를 공유받지 못한다.

  * getAuthentication()이나 getPrincipal()을 사용하지 못한다. 


## `해결방법` 
> SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL); 메서드 설정 

* 어디까지 공유할 것인가 범위를 설정하는것.
  * 기본은 쓰레드 로컬이지만, 설정을 변경할 수 있다.  

* SecurityContext를 자식 쓰레드에도 공유하는 전략.

* @Async를 처리하는 쓰레드에서도 SecurityContext를 공유받을 수 있다.
* 보통 SecurityConfig 내에서 사용 . 

참고
* https://docs.oracle.com/javase/7/docs/api/java/lang/InheritableThreadLocal.html

---
## SecurityContext 영속화 필터: SecurityContextPersistenceFilter

* 보통 필터 목록중 2번째에 등록된 필터
* 여러 요청 간에 SecurityContextHolder를 공유할 수 있는 기능 제공 
* 

* SecurityContextRepository를 사용해서 기존의 SecurityContext를 읽어오거나 초기화 한다.
  * 기본으로 사용하는 전략은 HTTP Session을 사용한다.
    * HTTP Session에서 읽어오는것이 기본 전략.  
  * Spring-Session​과 연동하여 세션 클러스터를 구현할 수 있다. (이 강좌에서는 다루지 않습니다.)
 
* 우리가 만약 커스텀한 인증 필터를 만들어 넣고 싶다면  
  `반드시 SecurityContextPersistenceFilter필터 뒤에 넣어야 한다!!!`.  
![](img/2021-01-02-18-48-21.png)


---
## 시큐리티 관련 헤더 추가하는 필터: HeaderWriterFilter
응답 헤더에 시큐리티 관련 `헤더를 추가`해주는 필터

* XContentTypeOptionsHeaderWriter​: 마임 타입 스니핑 방어.
  * >X-Content-Type-Options: nosniff   
     이 헤더는 리소스를 다운로드 할때 해당 리소스의 MIMETYPE이 일치하지 않는 경우 차단을 할 수 있다. 
      위 처럼 설정하는 경우 styleSheet는 MIMETYPE이 text/css와 일치할 때까지 styleSheet를 로드하지 않는다. 
      또한 공격자가 다른 확장자(jpg)로 서버에 파일을 업로드 한 후 
      script태그등의 src의 경로를 변경하여 script를 로드 하는 등의 공격을 막아준다.

* XXssProtectionHeaderWriter​: 브라우저에 내장된 XSS 필터 적용.
  * > 이 헤더는 공격자가 XSS공격을 시도할 때 브라우저의 내장 XSS Filter를 통해 공격을 방지할 수 있는 헤더
      위 처럼 설정한 경우 브라우저가 XSS공격을 감지하면 자동으로 내용을 치환한다.
      mode=block 유무에 따라 내용만 치환 하고 사용자화면에 보여주거나 페이지 로드 자체를 block할 수 있다.   
     위 헤더는 브라우저의 내장 XSS Filter에 의해 처리 되므로 각 브라우저마다 처리 방식이 다를 수 있다.
     모든 공격을 막을 수는 없기 때문에 추가적으로 Filter를 설정하여 방어해야 한다.
     X-XSS-Protection: 1; mode=block
     
* CacheControlHeadersWriter​: 캐시 히스토리 취약점 방어.
  * > 공격자가 브라우저의 히스토리를 통한 공격을 진행 할 수 있기 때문에 cache를 적용하지 않는다는 헤더 
      Cache-Control: no-cache, no-store, max-age=0, must-revalidate  
      Pragma: no-cache  
      Expires: 0

* HstsHeaderWriter: HTTPS로만 소통하도록 강제.
  * > 이 헤더는 한번 https로 접속 하는 경우 이후의 모든 요청을 http로 요청하더라도 브라우저가 자동으로 https로 요청  
      Strict-Transport-Security: max-age=31536000;includeSubDomains;preload   
      https로 전송한 요청을 중간자가 가로채어 내용을 볼 수 있는(MIMT)기법을 클라이언트 레벨(브라우저)에서 차단   
      또한 2014년 블랙햇 아시아 컨퍼런스에서 "Leonard Nve Egea"가 sslStrip+ 를 공개하면서  
      서브도메인을 통해 우회할 수 있는 방법에 대해 includeSubDomains 를 추가하여 차단할수 있다.

* XFrameOptionsHeaderWriter​: clickjacking 방어
  * > 이 헤더는 한번 https로 접속 하는 경우 이후의 모든 요청을 http로 요청하더라도 브라우저가 자동으로 https로 요청  
     Strict-Transport-Security: max-age=31536000;includeSubDomains;preload  
     https로 전송한 요청을 중간자가 가로채어 내용을 볼 수 있는(MIMT)기법을 클라이언트 레벨(브라우저)에서 차단  
    또한 2014년 블랙햇 아시아 컨퍼런스에서 "Leonard Nve Egea"가 sslStrip+ 를 공개하면서 서브도메인을 통해 우회할 수   
    있는 방법에 대해 includeSubDomains 를 추가하여 차단할수 있습니다. 


// Response의 헤더
```
// Resopnse Header
HTTP/1.1 200
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Type: text/html;charset=UTF-8
Content-Language: ko-KR
Transfer-Encoding: chunked
Date: Wed, 22 Aug 2019 17:18:41 GMT
Keep-Alive: timeout=60
Connection: keep-alive
```
*** 출처 - [참고 사이트](#https://cyberx.tistory.com/171)  
  * [참고 사이트](#https://github.com/GentleDot/spring-security-demo)

![](img/2021-01-02-20-37-34.png)

참고
* X-Content-Type-Options:
  * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
* Cache-Control:
  * https://www.owasp.org/index.php/Testing_for_Browser_cache_weakness_(OTGAUTHN-006)
* X-XSS-Protection
  * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection
  * https://github.com/naver/lucy-xss-filter
* HSTS
  * https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
* X-Frame-Options○ 
  * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options

* https://cyberx.tistory.com/171

--- 
## CSRF 어택 방지 필터: CsrfFilter

CSRF (Cross-site request forgery) : 원치 않는 요청을 임의대로 만들어 보내는것. 

CSRF 어택 방지 필터
* 인증된 유저의 계정을 사용해 악의적인 변경 요청을 만들어 보내는 기법.

* https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)

* https://namu.wiki/w/CSRF

* CORS를 사용할 때 특히 주의 해야 함.
  * 타 도메인에서 보내오는 요청을 허용하기 때문에...
  * https://en.wikipedia.org/wiki/Cross-origin_resource_sharing

![](img/2021-01-02-21-26-53.png)

의도한 사용자만 리소스를 변경할 수 있도록 허용하는 필터
* `CSRF 토큰을 사용하여 방지.`

![](img/2021-01-02-21-27-19.png)

* public final class CsrfFilter extends OncePerRequestFilter
  * request.setAttribute(CsrfToken.class.getName(), csrfToken)
  * request.setAttribute(csrfToken.getParameterName(), csrfToken)
  * if (!csrfToken.getToken().equals(actualToken)) {}

* CSRF 토큰을 사용하여 방지.


### CSRF 토큰 사용하지 않는 법 
```JAVA
// SecurityConfig 클래스 내 configure(HttpSecurity http) 메서드 
 @Override
    protected void configure(HttpSecurity http) throws Exception {
         http.csrf().disable();
    }
```
  * FilterChainProxy 클래스내의 필터를 확인해보면 CSRF 필터가 빠진 걸 확인 가능  


## `폼기반 웹 페이지 애플리케이션에서는 반드시 사용하는 것이 좋다.`
  * 특히 요청으로 리소스 변경 하는 경우 


## CSRF 토큰 사용 예제

JSP에서 스프링 MVC가 제공하는 <form:form> 태그 또는  
타임리프 2.1+ 버전을 사용할 때 폼에
`CRSF 히든 필드`가 기본으로 생성 된다.

* csrf token 없이 POST 회원가입 요청을 보내면 , `401 Unauthorized` 에러가 발생
  * csrf 토큰 값이 없어서 폼 인증이 되지 않기 때문 .


* CSRF 토큰 테스트
```java

@SpringBootTest
@AutoConfigureMockMvc
class SignUpControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    public void signUpForm() throws Exception {
        mockMvc.perform(get("/signup"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("_csrf")));
    }

    @Test
    public void processSignUp() throws Exception {
        mockMvc.perform(post("/signup")
                .param("username", "youngsoo3")
                .param("password", "1234")
                .with(csrf())) // csrf 토큰 포함하여 요청 전송 
                .andDo(print())
                .andExpect(status().is3xxRedirection());
    }
}
```
* TEST 상에서 csrf 설정이 없으면 403(forbidden) 되어 테스트가 실패.
  * `.with(csrf()) 추가 필요.`
* org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf

---

## 로그아웃 처리 필터: LogoutFilter
여러 LogoutHandler를 사용하여 로그아웃시 필요한 처리를 하며 이후에는
LogoutSuccessHandler를 사용하여 로그아웃 후처리를 한다.

LogoutHandler
  * CsrfLogoutHandler
  * SecurityContextLogoutHandler

LogoutSuccessHandler
  * SimplUrlLogoutSuccessHandler

### 로그아웃 필터 설정

```java
http.logout()
     .logoutUrl("/logout")       // logout 처리할 페이지 설정
     .logoutSuccessUrl("/")      // logout 성공 시 redirect 페이지 설정
     .addLogoutHandler()         // logout 시 부가적인 작업 설정 
     .logoutSuccessHandler();    // logout 성공 시 부가적인 작업 설정
     .invalidateHttpSession(true)// logout 시 HttpSession invalidated 
     .deleteCookies()            // Cookie 기반 인증 사용 시 logout 할 때      Cookie 삭제
     .logoutRequestMatcher()
```

* 기본적으로 2개의 logoutHandler 사용
  * CsrfLogoutHandler
  * SecurityContextLogoutHandler 

![](img/2021-01-03-15-03-33.png)

---
## 폼 인증 처리 필터: UsernamePasswordAuthenticationFilter
폼 로그인을 처리하는 인증 필터

* 사용자가 폼에 입력한 username과 password로 Authentcation을 만들고  
   AuthenticationManager를 사용하여 인증을 시도한다.

1.  AuthenticationManager (ProviderManager)는 여러 AuthenticationProvider를 사용하여 인증을 시도
   
2. 그 중에 DaoAuthenticationProvider는 UserDetailsServivce를 사용하여 UserDetails 정보를 가져오고
3.  사용자가 입력한 password와 가져온 정보를 비교한다


![](img/2021-01-03-15-19-00.png)

--- 

## 로그인/로그아웃 폼 페이지 생성해주는 필터: DefaultLogin/LogoutPageGeneratingFilter
스프링 시큐리티 기본 로그인 폼 페이지를 자동으로 생성해주는 필터

* GET /login 요청을 처리하는 필터

로그인 폼을 커스터마이징 할 수 있다. SecurityConfig 내의 configure 메서드
```java
// 폼 로그인 사용 시 기본 파라미터 이름에서 우리가 원하는 파라미터 이름으로 바꿀 수 있다.
http.formLogin()
 .usernameParameter("my-username")
 .passwordParameter("my-password");
```
![](img/2021-01-03-15-33-10.png)


## 우리가 만약 로그인 페이지를 커스텀 해서 사용할 것이면?
시큐리티 설정 내에서 로그인 페이지를 따로 설정 해줘야 한다

```java
http.formLogin()
        .loginPage("/my-login-page")
        .permitAll();
```
* 이렇게 설정 하면 커스텀 페이지를 사용할 것이라고 선언한 거기 때문에  
  두 필터를 제공 해주지 않는다.  (필터 등록 x )
    * DefaultLoginPageGeneratingFilter 필터 등록이 안되있다
    * 로그 아웃도 마찬가지. (DefaultLogoutPageGeneratingFilter)
    * 다른 필터들은 등록 되어있다.  
    * 반드시 .permitAll()을 해줘야 한다 (모든 사용자 접근 가능하게)
      
> 어떻게 해야 할 것인가? 
> 다음 참조 -> [링크](#로그인/로그아웃-폼-커스터마이징)
 
![](img/2021-01-03-15-30-36.png)

---

## 로그인/로그아웃 폼 커스터마이징
문서 : https://docs.spring.io/spring-security/site/docs/current/reference/html5/#jc-form

* 시큐리티 설정 
```java
// SecurityConfig 클래스 내 메서드

@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
            .loginPage("/my-login-page")
            .permitAll();
    http.logout()
            .logoutUrl("/my-logout")
            .logoutSuccessUrl("/");
}
```

* 커스텀 로그인 페이지 my-login-page.html
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
<h1>Login</h1>
<div th:if="${param.error}">
    <div class="alert alert-danger">
        Invalid username or password.
    </div>
</div>
<form action="/my-login-page" th:action="@{/my-login-page}" method="post">
    <p>Username: <input type="text" name="username" /></p>
    <p>Password: <input type="password" name="password" /></p>
    <p><input type="submit" value="login" /></p>
</form>
</body>
</html>

```

* 커스텀 로그아웃 페이지 - my-logout-page.html
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Logout</title>
</head>
<body>
<h1>Logout</h1>
<form action="/my-logout" th:action="@{/my-logout}" method="post">
    <p><input type="submit" value="logout" /></p>
</form>
</body>
</html>
```

* 커스텀 로그인 / 로그아웃 Controller

```java
@Controller
public class LogInOutController {
    @GetMapping("/my-login-page")
    public String loginForm() {
        return "my-login-page";
    }

    @GetMapping("/my-logout-page")
    public String logout() {
        return "my-logout-page";
    }

}
```

* FilterChainProxy 내의 Filter 목록 디버그로 찍어 본 결과.

![](img/2021-01-03-16-05-46.png)
* 필터 목록을 보면 몇 필터가 빠진지 알 수 있다. 
    * DefaultLoginPageGeneratingFilter -> x
    * DefaultLogoutPageGeneratingFilter -> x

* 커스텀한 로그인 페이지를 설정했기 때문에 필터가 사라진다
  * 우리가 따로 구현해서 지정해 줘야 한다.  

* 로그아웃 뷰도 없어지기 때문에 우리가 같이 만들어 줘야 한다. 

* POST 요청은 스프링 시큐리티가 제공하는 UserNamePassowrdAuthenticationFItler가 처리 하도록 사용
   

---

## Basic 인증 처리 필터: BasicAuthenticationFilter

Basic 인증이란?
* https://tools.ietf.org/html/rfc7617
* 요청 헤더에 username와 password를 실어 보내면 브라우저 또는 서버가 그 값을 읽어서
인증하는 방식. 
  * 예) Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l  
       (keesun:123을 BASE 64)

* 보통, 브라우저 기반 요청이 클라이언트의 요청을 처리할 때 자주 사용.

* 보안에 취약하기 때문에 반드시 HTTPS를 사용할 것을 권장.

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.basic();
}
```

* UsernamePasswordAuthenticationFilter와의 비교

* |Http Basic|UsernamePassword|
  |--|--|
  |param : username, password| form|
  |Request Header에서 읽음| Form Request(요청)에서 읽음|
  |stateless context(인증상태를 저장하지 않음)| stateful (SessionRepository 캐시하여 context(인증상태) 저장|  

<br>

* BasicAuthenticationFilter.doFilterInternal 메소드 안에   
  this.rememberMeServices.loginSuccess(request, response, authResult);가  
  호출되는 부분이 있는데 여기에서 쿠기가 발급

* postman을 이용해서 basic authentication을 실행한 결과       
  SecurityContextPersistenceFilter finally 스코프에서 session에  
  authentication 정보를 넣어 준다.

* postman에서 basic authentication 후 발급 받은 쿠키만 있다면   
  이후 다음 요청에 authorization basic 헤더 필드가 없어도 인증된 결과를  확인할 수 있다. 

* statefull과 stateless의 차이는 인증 방법(basic, form)이 아니라   
  http client의 차이

---

## 요청 캐시 필터: RequestCacheAwareFilter
RequestCacheAwareFilter.class 

현재 요청과 관련 있는 캐시된 요청이 있는지 찾아서 적용하는 필터.
* 캐시된 요청이 없다면, 현재 요청 처리
* 캐시된 요청이 있다면, 해당 캐시된 요청 처리

예)
> 대시보드(로그인이 필요한 페이지) 페이지를 접속하려고 하면 로그인 페이지로 이동. (현재 인증 되지 않았기 때문. 이때 캐싱한다. )   
> 로그인 페이지에서 로그인 인증을 수행하고 나면,   
> RequestCacheAwareFilter에서 캐시한 요청(대시보드 페이지로 이동 요청)을 수행

---

## 시큐리티 관련 서블릿 스팩 구현 필터: SecurityContextHolderAwareRequestFilter

시큐리티 관련 서블릿 API를 구현해주는 필터
* HttpServletRequest#authenticate(HttpServletResponse)
* HttpServletRequest#login(String, String)
* HttpServletRequest#logout()
* AsyncContext#start(Runnable)

---

## 익명 인증 필터: AnonymousAuthenticationFilter
https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#anonymous

아무도 인증하지 않은 요청인 경우
현재 SecurityContext에 Authentication이 null이면 “익명 Authentication”을 만들어 넣어주고, null이 아니면 아무일도 하지 않는다.

기본으로 만들어 사용할 “익명 Authentication” 객체를 설정할 수 있다
 
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.anonymous()
            .principal()
            .authorities()
            .key()
}
```

*  Authentication이 null이면 “Anonymous(익명) Authentication” 
   `널 오브젝트 패턴` 객체를 생성하여 넣는다. 

### 널 오브젝트 패턴 (Null Object pattern)
* 널 오브젝트는 널이 아니다
* Null 대신 Null의 성격이랑 비슷한 Object를 생성
* 코드에서 NULL 체크를 하는게 아니라 NULL을 대변하는 객체를 넣는것

참고
* https://en.wikipedia.org/wiki/Null_object_pattern

---

## 세션 관리 필터: SessionManagementFilter

https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#session-mgmt

세션 변조 방지 전략 설정: sessionFixation
* 세션 변조: ​https://www.owasp.org/index.php/Session_fixation
    * 공격자가 웹 사이트에 로그인해서 자기의 세션 아이디를 쿠키를 받아      
      공격할 사람한테 보내서 그 세션 아이디를 가지고 서버를 헷갈리게 해서 정보를 탈취하는것  

* 세션 변조 방지 설정
  * http.sessionManagement().sessionFixation()      
    * none() : 방지를 하지 않는다. 
    * newSession() : 매번 새로운 세션을 만든다
    * migrateSession() (서블릿 3.0- 컨테이너 사용시 기본값)
    * changeSessionId()​ (서브릿 3.1+ 컨테이너 사용시 기본값)

* https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#nsa-session-management-attributes

유효하지 않은 세션을 리다이렉트 시킬 URL 설정
* http.sessionManagement()
  * invalidSessionUrl()

# 동시성 제어: maximumSessions
* 추가 로그인을 막을지 여부 설정 (기본값, false)
    * 기본적으로는 한 계정으로 여러 로그인 할 수 있게 설정 되어 있다.
      
    * http.sessionManagement().maximumSessions() : 세션 개수 설정
    
    * maxSessionsPreventsLogin() : 추가 로그인을 막을지 말지 설정 (default = false)
      * 세션이 1개인데 `false로 두고` 다중 로그인을 하면 로그인이 되면서    
        다른로그인 중이던 아이디는 세션이 해제되고 session expire라는 문구가 나온다.

      *  반대로 `true로 두고` 다중 로그인을 시도하면 아예 로그인이 안된다 



* https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#nsa-concurrency-control

세션 생성 전략: sessionCreationPolicy . 4가지 

* http.sessionManagement().sessionCreationPolicy()
  1. IF_REQUIRED (Default) : 필요할 때 session 생성
  2. NEVER : Security에서는 session 생성 안하고 외부 session 사용
  3. STATELESS : session 생성하지 않음. (정말 세션을 쓰고싶지 않다면 사용)
     * REST API 등을 구현할 때 사용하는 전략  
  4. ALWAYS

---
## 인증/인가 예외 처리 필터: ExceptionTranslationFilter

https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#exceptiontranslation-filter

### 인증, 인가 에러 처리를 담당하는 필터
* AuthenticationEntryPoint
* AccessDeniedHandler

* try-catch 구문으로 감싸고 FilterSecurityInterceptor를 처리한다
* FilterSecurityInterceptor는 AccessDecisionManager를 이용해서 인가 처리를 함
* AuthenticationEntryPoint, AccessDeniedException 예외를 처리함
    * AuthenticationException은 AuthenticationEntryPoint를 사용해서 예외처리 
      * AuthenticationEntryPoint은 유저를 인증을 할 수 있게 끔 인증이 가능한 페이지로 보낸다. 
     
    * AccessDeniedException은 AccessDeniedHandler를 사용해서 처리한다. 
      * 기본 처리는 403 에러  

```java
// 핸들러 없이. 서버 쪽 로그는 안남는다.
http.exceptionHandling()
            .accessDeniedPage("/access-denied");

// 핸들러 구현. 서버 쪽 로그를 남길 수 있다.
 http.exceptionHandling()
            .accessDeniedHandler(new AccessDeniedHandler() {
                @Override
                public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,          
                                   AccessDeniedException e) throws IOException, ServletException {
                    UserDetails principal = (UserDetails) SecurityContextHolder.getContext()
                                                                                .getAuthentication().getPrincipal();
                    String username = principal.getUsername();
                    System.out.println(username + " is denied to access " + httpServletRequest.getRequestURI());
                    httpServletResponse.sendRedirect("/access-denied");
                }
            });
// 람다 식으로 작성도 가능!! (어나니머스 객체 대신) 
```
* 액세스 디나이가 발생하면 어느 페이지를 보여 줄 것인가를 설정

* 로그로 남겨 서버단에서 확인하려면 핸들러를 작성하면 된다. (누가 계속 비정상적인 접근을 하는 지 등)
* 핸들러를 구현하려면 따로 클래스를 작성해서 빈으로 등록한 다음 설정하면 된다.
    * http.exceptionHandling().accessDeniedHandler();

ExceptionTranslationFitler와 FilterSecurityInterceptor랑은 밀접한 관계가 있다. 
  * 필터 순서가 ExceptionTranslationFitler가 더 앞에 있어야 한다.

---

## 인가 처리 필터: FilterSecurityInterceptor

* https://docs.spring.io/spring-security/site/docs/5.1.5.RELEASE/reference/htmlsingle/#filter-security-interceptor

* HTTP 리소스 시큐리티 처리를 담당하는 필터. 

* `AccessDecisionManager를 사용하여 인가`를 처리한다.
 
* HTTP 리소스 시큐리티 설정

```java
// SecurityConfig.class
http.authorizeRequests()
    .mvcMatchers("/", "/info", "/account/**", "/signup").permitAll()
    .mvcMatchers("/admin").hasAuthority("ROLE_ADMIN")
    .mvcMatchers("/user").hasRole("USER")
    .anyRequest().authenticated()
    .expressionHandler(expressionHandler());
```

* mvcMatches() : Spring MVC 패턴하고 매칭이 되는지. antPattern으로 폴 백 됨
  * regexMatchers를 사용하거나 antMatchers도 사용 가능 
* permitAll() : 모두에게 허용  
* hasRole() : 권한이 있는지. Authority가 상위개념  
* hasAuthority() : 권한이 있는지. Role의 상위개념 
  * hasAuthority() 를 사용시 ROLE_를 붙여줘야 한다 ex) hasAuthority("ROLE_USER"); 
   
* anyRequest()
  * .anonymous() : 익명 사용자에게만 접근할 수 있게 하는것
    * 인증을 하고 접근하면 접근이 거부가 된다.  
  
  * .authenticated() : 인증이 되기만 하면 접근 가능
  * .rememeberMe() : 리멤버 미 기능으로 인증한 사용자 접근 가능
  * .fullyAuthenticated() : 리멤버 미로 인증이 된 사용자에게 다시 인증을 요구 
    * 인증이 된 사용자도 한번 더 인증(로그인)을 요구하는것.  
    * 가령 장바구니에서 주문할 때 다시 한번 더 인증을 확인하는거 
  * .denyAll() : 아무것도 허용하지 않겠다. 
  * .not() : 뒤에 조건이 아닌 경우 허용 ex) .not().anonymous() : 익명사용자가 아닌경우 허용 
    
![](img/2021-01-03-22-43-23.png)

여기까지가 기본적으로 사용되는 15개의 필터 설명이였다. 

추가적으로는 CORS나 Remember-ME 관련 필터 등록 가능하다. 

---

## 토큰 기반 인증 필터 : RememberMeAuthenticationFilter
* 세션이 사라지거나 만료가 되더라도 쿠키 또는 DB를 사용하여 저장된 토큰 기반으로 인증을 지원하는 필터
* 체크박스로 로그인 기억! 해놨을 때 명시적으로 로그아웃 하지 않는이상 계속 로그인 되있는 것

* RememberMe 설정 
```JAVA
http.rememberMe()
     .userDetailsService(accountService)  // UserDetailsSerivce인터페이스를 구현한 서비스 
         .key("remember-me-sample");
         .rememberMeParameter("rememberParam") // 파라미터 이름. default = remember-me
         .tokenValiditySeconds() // 쿠키 유지 시간. default = 2주
         .useSecureCookie() // HTTPS 접근만 쿠키 사용이 가능하도록 설정
         .alwaysRemember()   // 항상 쿠키 생성, default = false
```

페이지에 접속하면 서버에서 세션이 생성되고 웹 브라우저 쿠키에 세션 아이디 정보(JSessionID)가 담긴다.   
로그인을 하면 서버는 해당 세션을 인증된 세션으로 취급.

사용자가 강제로 웹 브라우저 쿠키에서 세션 아이디를 삭제하게 되면,  
인증된 세션이 아니기 때문에 서버는 다시 로그인 창으로 리다이렉트 된다.

세션 아이디를 삭제하면 SecurityContextHolder에서 인증 정보를 가져올 수 없기에   
서버는 인증되지 않은 사용자로 판단, 인증이 필요한 페이지나 리소스의 접속을 제한


쿠키 플러그인
* https://chrome.google.com/webstore/detail/editthiscookie/fngmhnnpilhplaeedifhccceomclgfbg?hl=en

---

## 커스텀 필터 추가하기

# 섹션 3. 스프링 시큐리티 그밖에

## 타임리프 스프링 시큐리티 확장팩

## sec 네임스페이스

## 메소드 시큐리티

## @AuthenticationPrincipal

## 스프링 데이터 연동

## 스프링 시큐리티 마무리
