Pod::Spec.new do |s|
  s.name         = "ZBOpenSSL"
  s.version      = "0.0.1"
  s.summary      = "OpenSSL tools!"
  s.description  = <<-DESC
                  This is a openssl tools!
                   DESC
  s.homepage     = "https://github.com/githubzb/ZBOpenSSL"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author             = { "dr.box" => "1126976340@qq.com" }
  s.platform     = :ios, "9.0"
  s.source       = { :git => "https://github.com/githubzb/ZBOpenSSL.git", :tag => "#{s.version}" }
  s.requires_arc = true
  s.source_files = "#{s.name}/Resource/**/*.{h,m}"
  s.dependency "GTMBase64", "~> 1.0.1"

  s.subspec "openssl" do |ossl|
    ossl.vendored_frameworks = "openssl.framework"
  end

end
