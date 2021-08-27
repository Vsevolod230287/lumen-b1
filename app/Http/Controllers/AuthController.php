<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;


class AuthController extends Controller
{

    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register','verifytoken','recover']]);
    }


    public function login(Request $request)
    {
        $email = $request->email;
        $password = $request->password;

        //Check if field is empty
        if(empty($email)or empty($password)){
            return response()->json(['status'=>'error', 'message'=>'You must fill all the fields']);
        }

        $credentials = request(['email', 'password']);

        if(! $token = auth()->attempt($credentials)) {

            return response()->json( ['status'=>'error', 'message'=>'Unauthorized'], 401 );
        }
        return $this->respondWithToken($token);


    }




    public function register(Request $request)  
    {
        $name = $request->name;
        $email= $request->email;
        $password = $request->password;

        //check if fields is empty
        if(empty($name) or  empty($email) or empty($password)){
            return response()->json(['status'=>'error','message'=>'You must enter a valid email']);
        }
    
        //check if email is valid
        if (! filter_var($email, FILTER_VALIDATE_EMAIL)){
            return response()->json(['status' => 'error','message'=>'You must enter a valid email']);
        }


        //check if password is grater than 5 characters:
        if(strlen($password) < 6){
            return response()->json(['status'=>'error','message'=>'Password should be min 6 character']);
        }
        try{

        // check if user already exist
        if( User::where('email', '=', $email)->exists() ){
            return response()->json(['status'=>'errors', 'message'=>'User already exists with this email']);
        }

        //create a new user
      
            $user = new User();
            $user->name = $name;
            $user->email = $email;
            $user->password = app('hash')->make($password);

            if($user->save()){
                return $this->login($request);
            }
         
        } catch (\Exception $e){
            return response()->json(['status'=>'error','message'=> $e->getMessage()]);
        }

    }



    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token'=> $token,
            'token_type' => 'bearer',
            'expires_in' =>auth()->factory()->getTTL() * 60
        ]);
    }

}
