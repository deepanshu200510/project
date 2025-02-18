const loginEmail=document.getElementById("email")
const password=document.getElementById("password")
const loginBtn=document.getElementById("login-button")
// const errorMessage=document.getElementById("error-message")


loginEmail.addEventListener('keydown',(event)=>{
    if(event.key=='Enter'){
        password.focus()
    }
   
})
password.addEventListener('keydown',(event)=>{
    if(event.key=='Enter'){
        profile=JSON.parse(localStorage.getItem('profile'))
        if(profile!=null){
            if(loginEmail.value==profile.email){
                if(password.value==profile.password){
                    window.location.href="../Home/tasktemp.html"
                }
                else{
                    alert("Incorrect Password")
                }
            }
            else{
                alert("Email isn't registered")
            }
        }
        else{
             alert("Email isn't registered")
        }
    }
})

loginBtn.addEventListener('click',function(){
    profile=JSON.parse(localStorage.getItem('profile'))
        if(profile!=null){
            if(loginEmail.value==profile.email){
                if(password.value==profile.password){
                    window.location.href="../Home/tasktemp.html"
                }
                else{
                    alert("Incorrect Password")
                }
            }
            else{
                alert("Email isn't registered")
            }
        }
        else{
             alert("Email isn't registered")
        }
})