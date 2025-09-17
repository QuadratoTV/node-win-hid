#include "MyObject.h"

using namespace Napi;

MyObject::MyObject(const Napi::CallbackInfo &info)
    : ObjectWrap(info)
{
    Napi::Env env = info.Env();

    if(info.Length() < 1)
    {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return;
    }

    if(!info[0].IsString())
    {
        Napi::TypeError::New(env, "You need to name yourself")
            .ThrowAsJavaScriptException();
        return;
    }

    this->_greeterName = info[0].As<Napi::String>().Utf8Value();
}

Napi::Value MyObject::Greet(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    if(info.Length() < 1)
    {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if(!info[0].IsString())
    {
        Napi::TypeError::New(env, "You need to introduce yourself to greet")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::String name = info[0].As<Napi::String>();

    printf("Hello %s\n", name.Utf8Value().c_str());
    printf("I am %s\n", this->_greeterName.c_str());

    return Napi::Value();
}

Napi::Value MyObject::Add(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    if(info.Length() < 2)
    {
        Napi::TypeError::New(env, "Wrong number of arguments")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if(!info[0].IsNumber() || !info[1].IsNumber())
    {
        Napi::TypeError::New(env, "You need to pass numbers")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    double a = info[0].As<Napi::Number>().DoubleValue();
    double b = info[1].As<Napi::Number>().DoubleValue();
    return Napi::Number::New(env, a + b);
}

Napi::Function MyObject::GetClass(Napi::Env env)
{
    return DefineClass(
        env,
        "MyObject",
        {
            MyObject::InstanceMethod("greet", &MyObject::Greet),
            MyObject::InstanceMethod("add", &MyObject::Add),
        });
}