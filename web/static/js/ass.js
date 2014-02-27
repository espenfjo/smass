var failed = false;

var active;

var blocked = false;



  $(document)
      .on('change', '.btn-file :file', function() {
          var input = $(this),
          numFiles = input.get(0).files ? input.get(0).files.length : 1,
          label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
          input.trigger('fileselect', [numFiles, label]);
  });

$(document).ready(function() {
    $('.btn-file :file').on('fileselect', function(event, numFiles, label) {        
        var input = $(this).parents('.input-group').find(':text'),
            log = numFiles > 1 ? numFiles + ' files selected' : label;
        
        if( input.length ) {
            input.val(log);
        } else {
            if( log ) alert(log);
        }
        
    });
    
    var url = window.location;
    $('.navbar .nav').find('.active').removeClass('active');
    $('.navbar .nav li a').each(function () {
        if (this.href == url) {
            $(this).parent().addClass('active');
        }
    });
    setupListeners();
    $.ajaxSetup({
        timeout: 1,
        retryAfter: 2e3
    });


});

function setupListeners() {
    $('#modules a').click(function (e) {
        e.preventDefault();
        $(this).tab('show');
    });
    $("#pe-toggler").click(function(){
        $(this).toggleClass('active, inactive');
    })
    
}
