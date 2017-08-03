require 'java'
require 'base64'
java_import 'burp.IBurpExtender'
java_import 'burp.IScannerCheck'
java_import 'burp.IScanIssue'
java_import 'burp.IHttpRequestResponse'
java_import 'burp.IHttpService'
java_import 'burp.IRequestInfo'
java_import 'burp.IHttpListener'
java_import 'burp.IScannerListener'


# Ruby base from https://github.com/raesene/burp_sample_plugins

class BurpExtender
  include IBurpExtender, IScannerCheck

  def registerExtenderCallbacks(callbacks)

    # set our extension name
    callbacks.setExtensionName("File Upload Traverser")


    #Register for Scanner Callbacks
    callbacks.registerScannerCheck(self)

    # obtain our output and error streams
    @stdout = java.io.PrintWriter.new(callbacks.getStdout(), true)
    @stderr = java.io.PrintWriter.new(callbacks.getStderr(), true)

    # write a message to our output stream
    @stdout.println("Uploader running")

    #Obtain an extension to the helpers object
    @helpers = callbacks.getHelpers()

    #Keep a reference to the callbacks
    @callbacks = callbacks

    #module switch
    @module_1a = true
    @module_2a = true

    # files
    @upload_files = {
        "0157e03014ebcaebb9abf549236dd81c0b0b878d.jpg" => "image/jpeg" ,
        "0157e03014ebcaebb9abf549236dd81c0b0b878d.pdf" => "application/pdf" ,
        "0157e03014ebcaebb9abf549236dd81c0b0b878d.docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ,
        "0157e03014ebcaebb9abf549236dd81c0b0b878d.png" => "image/png"
    }

    @win_traverse = "..\\"
    @unix_traverse = "../"


  end


  # baseRequestResponse IHttpRequestResponse https://portswigger.net/burp/extender/api/burp/IHttpRequestResponse.html
  def doActiveScan(baseRequestResponse,insertionPoint)

    #https://portswigger.net/burp/extender/api/burp/IRequestInfo.html
    i_request = @helpers.analyzeRequest(baseRequestResponse)
    i_service = baseRequestResponse.getHttpService()


    # Multi Part request
    if i_request.getContentType() == 2

      # Only do for requests that have an insertion point filename
      if insertionPoint.getInsertionPointName().match(/filename/)

        #-----------------#
        #--- Module 1a ---#
        #-----------------#
        if @module_1a
          @stdout.println "Running 1a"
          depth=5
          filename_payloads=Array.new
          sub_folders = getFoldersFromSitemap(i_service.getHost)

          @upload_files.each do |filename, ct|
            traversal = generateTraversal(filename,sub_folders,depth,"all")

            traversal.each do |full_file_path|
             # @stdout.println full_file_path
              filename_payloads.push full_file_path
              response = send_repackage_upload(baseRequestResponse, full_file_path)
              #@stdout.println @helpers.bytesToString response.getResponse

            end
          end


          url_paths = getVerificationURLS(i_service.getHost,i_service.getPort)
          verified_urls = verifyUrlsExist(url_paths, baseRequestResponse)

          unless verified_urls.empty?
            finding = CustomScanIssue.new
            finding.httpMessages=baseRequestResponse
            finding.httpService=baseRequestResponse.getHttpService()
            finding.url= @helpers.analyzeRequest(baseRequestResponse).getUrl()
            finding.name = "File Upload Traverser - Uploaded file in webroot detected - Module 1a"
            finding.detail = "The following files have been successfully uploaded to the server:<br/><br/> #{verified_urls.join("<br/>")}"
            finding.severity = "High"
            finding.confidence = "Certain"
            finding.remediation_detail = "Check filenames based on a whitelist filter that only accepts files with specific file extensions and that does not allow directory traversal such \"../\" or \"\\..\" . For more information on directory traversal see http://cwe.mitre.org/data/definitions/22.html"
            finding.issue_background = "The following filename payloads have been used: <br/><br/> #{filename_payloads.join("<br/>")}"
            @callbacks.addScanIssue(finding)
          end
        end

        #-----------------#
        #--- Module 2a ---#
        #-----------------#

        if @module_2a
          @stdout.println "Running 2a"
          path_disclosures = getPathDisclosures(baseRequestResponse, i_service)
          file = File.open("files/dir_names.txt", "r")
          content = file.read
          file.close

          path_disclosures_filtered = Array.new
          path_disclosures.each do |p|
            dir = content.split("\n")
            dir.each do |d|
               if p.match(/#{d}/)
                 path_disclosures_filtered.push p
               end
            end
          end
          path_disclosures_filtered.uniq!


          unless path_disclosures_filtered.empty?
            finding = CustomScanIssue.new
            finding.httpMessages=baseRequestResponse
            finding.httpService=baseRequestResponse.getHttpService()
            finding.url= @helpers.analyzeRequest(baseRequestResponse).getUrl()
            finding.name = "File Upload Traverser - Abosulte Path Disclosure - Module 2a"
            finding.detail = "The following absolute path disclosures have been discovered. The discovery of absolute path disclosures in error messages might include false positives:<br/><br/> #{path_disclosures_filtered.join("<br/>")}"
            finding.severity = "Low"
            finding.confidence = "Tentative"
            finding.remediation_detail = "It is advised to turn off verbose error messages and replace it with generic error pages that do not disclose sensitive technical information."
            finding.issue_background = " The engine tries to discover path disclosures from issues found by the error message check extension and from a quick fuzz run <br/><br/> "
            @callbacks.addScanIssue(finding)
          end

          traverse_first = ""
          traverse_second_list = Array.new
          filename_payloads=Array.new


          path_disclosures_filtered.each do |path_disclosure|
            @upload_files.each do |filename, ct|

              sub_folders = getFoldersFromSitemap(i_service.getHost)
              if path_disclosure.match(/\//)
                traverse_first = @unix_traverse * 12
                traverse_second_list = generateTraversal(filename,sub_folders,3,"unix")
              else
                traverse_first = @win_traverse * 12
                traverse_second_list = generateTraversal(filename,sub_folders,3,"win")
              end

              traverse_second_list.each do |traverse_second|
                full_file_path = traverse_first + path_disclosure + traverse_second
               # @stdout.println full_file_path
                filename_payloads.push full_file_path
                response = send_repackage_upload(baseRequestResponse, full_file_path)
              end
            end
          end
          url_paths = getVerificationURLS(i_service.getHost,i_service.getPort)
          verified_urls = verifyUrlsExist(url_paths, baseRequestResponse)

          unless verified_urls.empty?
            finding = CustomScanIssue.new
            finding.httpMessages=baseRequestResponse
            finding.httpService=baseRequestResponse.getHttpService()
            finding.url= @helpers.analyzeRequest(baseRequestResponse).getUrl()
            finding.name = "File Upload Traverser - Uploaded file in webroot detected - Module 2b"
            finding.detail = "The following files have been successfully uploaded to the server:<br/><br/> #{verified_urls.join("<br/>")}"
            finding.severity = "High"
            finding.confidence = "Certain"
            finding.remediation_detail = "Check filenames based on a whitelist filter that only accepts files with specific file extensions and that does not allow directory traversal such \"../\" or \"\\..\" . For more information on directory traversal see http://cwe.mitre.org/data/definitions/22.html"
            finding.issue_background = "The following filename payloads have been used: <br/><br/> #{filename_payloads.join("<br/>")}"
            @callbacks.addScanIssue(finding)
          end
        end
      end
    end
  end

  def verifyUrlsExist(url_paths,baseRequestResponse)
    verified_urls= Array.new
    url_paths.each do |url_path|
      @upload_files.each do |filename,ct|
        url = url_path + filename
        if verify_upload(baseRequestResponse,url )
          verified_urls.push url
        end
      end
    end
    verified_urls
  end


  # Get path disclosures from error check extension and from quick fuzz run
  # Could also use the launchPassiveScan(i_service, response) function for the fuzz run
  def getPathDisclosures(baseRequestResponse,i_service)
    path_disclosure = Array.new

    file = File.open("/Users/thec00n/work/research/burp_plugins/Uploader/files/fuzz.txt", "r")
    content = file.read
    file.close

    lines = content.split("\n")
    lines.each do |line|
      response = send_repackage_upload(baseRequestResponse,line)
      path_disclosure.concat extractPath(@helpers.bytesToString response.getResponse)
    end

    issues = @callbacks.getScanIssues(i_service.getProtocol + "://" +i_service.getHost)
    issues.each do |issue|
      name = issue.getIssueName
      if name.match(/Detailed Error Messages/)
        messages = issue.getHttpMessages()
        messages.each do |m|
          path_disclosure.concat extractPath(@helpers.bytesToString m.getResponse)
        end

      end
    end
    path_disclosure.uniq
  end

  def generateTraversal(filenname,sub_folders,deep,filter)
    attack_win = Array.new(1,"")
    attack_unix = Array.new(1,"")
    all_path =  Array.new

  #  @stdout.println attack_win.last

    if filter.match(/win/) || filter.match(/all/)
      #attack_win.push (@win_traverse)
      deep.times do
        attack_win.push (attack_win.last + @win_traverse)
      end
      all_path.concat(attack_win)
    end

    if filter.match(/unix/) || filter.match(/all/)
     # attack_unix.push (@unix_traverse)
      deep.times do
        attack_unix.push (attack_unix.last + @unix_traverse)
      end
      all_path.concat(attack_unix)
    end

    all = Array.new
    all_path.each do |item|
      unless sub_folders.nil?
        sub_folders.each do |sub_folder|
          s = sub_folder
          if item.match(/\\/)
            s=  sub_folder.gsub("/","\\")
          end
          s= "" if s =="/"
          all.push item + s + filenname
        end
      else
        all.push item + filenname
      end
    end
    all
  end

  def getVerificationURLS(host,port)
    folders=Array.new
    sitemap = @callbacks.getSiteMap(nil)
    sitemap.each do |item|

      url= @helpers.analyzeRequest(item).getUrl()

      if url.to_s.match(/#{host}/)
        url_first = url.getProtocol() + "://" + host
        url_first+= ":" + port.to_s if port.to_s != 443 or port.to_s != 80

        path = url.getPath()
        folder = path.slice(0..path.rindex(/\//))
        folders.push url_first + folder
        folders.push url_first + folder + "/upload/"
        folders.push url_first + folder + "/uploads/"

      end
    end

    folders.uniq
  end

  def getFoldersFromSitemap(host)
    folders=Array.new
    sitemap = @callbacks.getSiteMap(nil)
    sitemap.each do |item|

      url= @helpers.analyzeRequest(item).getUrl()

      if url.to_s.match(/#{host}/)
        path = url.getPath()
        folder = path.slice(0..path.rindex(/\//))
        folders.push folder
      end
    end

    folders.uniq
  end


  def replace_body(old_body,full_file_path,file_content,content_type,i_request)
    boundary=""
    i_request.getHeaders.each do |header|
      c = header.scan(/Content-Type:\smultipart\/form-data; boundary\=(.+)/).join
      if c != ""
        boundary = "--" + c
        #@stdout.println boundary
      end

    end

    body_parts = old_body.split(/#{boundary}/)

    new_body=boundary

    body_parts.each do |b|

      #@stdout.println "Part: " + b
      if filename = b.match(/filename\=\"(.+)\"/)
        part = b.gsub(filename[1],full_file_path)

        # replace the content-type with the correct one
        contenttype_old = b.match(/Content-Type:\s(.+)/)

        # replace the content-type with the correct one
        part = part.gsub(contenttype_old[0],"Content-Type: " + content_type)


        # Burp seems to fill in these values for file content
        content = b.match(/#{contenttype_old[0]}\n\r\n(.+)/m)
        part = part.gsub(content[1],"#{file_content}\r\n\r\n")

        new_body = new_body + part + boundary
      elsif b.match(/--\r\n/)
        new_body =  new_body  + b
      elsif b == ""
        #  @stdout.println "There is an an empty string somewhere"
      else
        new_body = new_body +  b + boundary
      end

    end
    new_body

  end

  def getHost(baseRequestResponse)
    baseRequestResponse.getHttpService().getHost
  end

  def getPort(baseRequestResponse)
    baseRequestResponse.getHttpService().getPort
  end

  def getProtocol(baseRequestResponse)
    baseRequestResponse.getHttpService().getProtocol
  end


  def isHTTPS(i_service)
    https = false
    https = true if i_service.getProtocol.match(/https/)
  end

  def getHeaders(i_request)
    headers=""
    i_request.getHeaders().each do |header|
      headers << header + "\r\n"
    end
    # @stdout.println "Print Headers:"
    # @stdout.println headers

    headers
  end


  # executed for all file types
  def send_repackage_upload(baseRequestResponse,full_file_path)

    filename=""
    content_type=""

    # get local filename and ct
    @upload_files.each do |f, ct|
      if full_file_path.match(/#{f}/)
        filename=f
        content_type=ct
      end
    end

    # if there is no matching filename select one from the list
    if filename.empty? || content_type.empty?

      values = @upload_files.keys
      filename = values[rand(values.size)]
      content_type = @upload_files[filename]

    end

    file = File.open("files/"+filename, "rb")
    file_content = file.read
    file.close

    # Get the request body
    i_request = @helpers.analyzeRequest(baseRequestResponse)
    request_body = @helpers.bytesToString(baseRequestResponse.getRequest()).split(/\r\n\r\n/,2)[1]

    new_request_body = replace_body(request_body, full_file_path , file_content, content_type, i_request)
    new_headers = getHeaders(i_request).gsub("Content-Length: " + request_body.length.to_s, "Content-Length: " + new_request_body.length.to_s)
    new_request = new_headers + "\r\n" + new_request_body

    response = @callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),@helpers.stringToBytes(new_request))

  end

  def extractPath (r)
    r = r.split("\r\n")
    all = Array.new
    r.each do |x|

      unix = x.scan(/(?:[\/0-9a-zA-Z_-]+\/){3,}/)

      unix.each do |p|
        if  p.length >10
          all.push p
        end
      end

      win = x.scan(/(?:[\\0-9a-zA-Z_-]+\\){3,}/)

      win.each do |p|
        if  p.length >10
          all.push p
        end
      end
    end
    all.uniq
  end


  def verify_upload(baseRequestResponse,url)
    request = @helpers.buildHttpRequest(java.net.URL.new(url));
    response = @callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),request).getResponse
    response_header =  @helpers.bytesToString(response).split("\r\n\r\n")[0]
    code = @helpers.analyzeResponse(response).getStatusCode()

    if code.to_s.match(/200/)
      @upload_files.each do |filename, ct|
        if url.match /#{filename}/
          if response_header.match (/#{ct}/)
            return true
          end
        end
      end
    end

    false
  end

  def doPassiveScan(response)
    return []
  end

  def launchPassiveScan(service,response)
    @callbacks.doPassiveScan(service.getHost,service.getPort,isHTTPS(service),response.getRequest,response.getResponse)
  end
end


class CustomScanIssue
  include IScanIssue
  def initialize
  end

  def httpMessages=(httpMessages)
    @httpMessages = httpMessages
  end

  def httpService=(httpService)
    @httpService = httpService
  end

  def name=(name)
    @name = name
  end

  def url=(url)
    @url = url
  end

  def detail=(detail)
    @detail = detail
  end

  def severity=(severity)
    @severity = severity
  end

  def confidence=(confidence)
    @confidence = confidence
  end

  def remediation_detail=(remediation_detail)
    @remediation_detail = remediation_detail
  end

  def issue_background=(issue_background)
    @issue_background = issue_background
  end

  def getUrl
    @url
  end

  def getHttpMessages
    [@httpMessages]
    #Alternate that also works
    #Java::JavaUtil::Arrays.as_list(@httpMessages).to_a
  end

  def getHttpService
    @httpService
  end

  def getRemediationDetail
    @remediation_detail
  end

  def getIssueDetail
    @detail
  end

  def getIssueBackground
    @issue_background
  end

  def getRemediationBackground
    return nil
  end

  def getIssueType
    return 0
  end

  def getIssueName
    @name
  end

  def getSeverity
    @severity
  end

  def getConfidence
    @confidence
  end
end
