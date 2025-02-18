const signUpUsername=document.getElementById("sign-up-username")
const signUpEmail=document.getElementById("sign-up-email")
const setPassword=document.getElementById("set-password")
const signUpBtn=document.getElementById("signup-button")

let profile={
    name:"",
    email:"",
    password:"",
}
signUpBtn.addEventListener("click",function(){
    profile.name=signUpUsername.value
    profile.email=signUpEmail.value
    profile.password=setPassword.value
    localStorage.setItem("profile",JSON.stringify(profile))
    // window.location.reload()
    window.location.href="../Home/task7.html"
})

const loginEmail=document.getElementById("email")
const password=document.getElementById("password")
const loginBtn=document.getElementById("log-in-button")
const errorMessage=document.getElementById("error-message")

loginBtn.addEventListener('click',function(){
    profile=JSON.parse(localStorage.getItem('profile'))
    if(profile!=null){
        if(loginEmail.value==profile.email){
            if(password==profile.password){
                window.location.href="../Home/task1.html"
            }
            else{
                errorMessage.textContent="Incorrect password"
            }
        }
        else{
            errorMessage.textContent="Email isn't registered"
        }
    }
    else{
        errorMessage.textContent="Email isn't registered"
    }
})