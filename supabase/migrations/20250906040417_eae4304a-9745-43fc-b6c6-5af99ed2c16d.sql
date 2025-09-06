-- Phase 1: Critical Security Fixes

-- Fix infinite recursion in profiles table by creating security definer function
CREATE OR REPLACE FUNCTION public.get_user_role()
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
DECLARE
    user_role TEXT;
BEGIN
    SELECT role INTO user_role 
    FROM profiles 
    WHERE id = auth.uid();
    
    RETURN COALESCE(user_role, 'unknown');
END;
$$;

CREATE OR REPLACE FUNCTION public.get_user_id()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = public
AS $$
BEGIN
    RETURN auth.uid();
END;
$$;

-- Drop existing problematic policies on profiles table
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.profiles;

-- Create new safe policies for profiles table
CREATE POLICY "Users can view own profile" 
ON public.profiles 
FOR SELECT 
USING (id = auth.uid());

CREATE POLICY "Users can update own profile" 
ON public.profiles 
FOR UPDATE 
USING (id = auth.uid());

CREATE POLICY "Users can insert own profile" 
ON public.profiles 
FOR INSERT 
WITH CHECK (id = auth.uid());

-- Enable RLS on tables that don't have it enabled
ALTER TABLE public.ai_algorithms ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.compliance_consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crt6_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.device_data_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.digital_signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.medical_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ostrc_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.pcma_assessments ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for tables missing them

-- AI Algorithms - Admin only access
CREATE POLICY "Admins can manage AI algorithms" 
ON public.ai_algorithms 
FOR ALL 
USING (get_user_role() = 'admin');

-- Compliance Consents - Users can view their own
CREATE POLICY "Users can view own consents" 
ON public.compliance_consents 
FOR SELECT 
USING (user_id = auth.uid());

CREATE POLICY "System can insert consents" 
ON public.compliance_consents 
FOR INSERT 
WITH CHECK (true);

-- CRT6 Assessments - Medical staff access
CREATE POLICY "Medical staff can manage CRT6 assessments" 
ON public.crt6_assessments 
FOR ALL 
USING (get_user_role() IN ('admin', 'physician', 'physiotherapist', 'trainer'));

-- Device Data Streams - Medical staff access
CREATE POLICY "Medical staff can manage device data" 
ON public.device_data_streams 
FOR ALL 
USING (get_user_role() IN ('admin', 'physician', 'physiotherapist', 'trainer'));

-- Digital Signatures - Medical staff access
CREATE POLICY "Medical staff can manage digital signatures" 
ON public.digital_signatures 
FOR ALL 
USING (get_user_role() IN ('admin', 'physician', 'physiotherapist'));

-- Medical Devices - Admin only
CREATE POLICY "Admins can manage medical devices" 
ON public.medical_devices 
FOR ALL 
USING (get_user_role() = 'admin');

-- OSTRC Assessments - Medical staff access
CREATE POLICY "Medical staff can manage OSTRC assessments" 
ON public.ostrc_assessments 
FOR ALL 
USING (get_user_role() IN ('admin', 'physician', 'physiotherapist', 'trainer'));

-- PCMA Assessments - Medical staff access
CREATE POLICY "Medical staff can manage PCMA assessments" 
ON public.pcma_assessments 
FOR ALL 
USING (get_user_role() IN ('admin', 'physician', 'physiotherapist', 'trainer'));

-- Update existing functions with proper security settings
CREATE OR REPLACE FUNCTION public.update_physio_documentation_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.update_performance_assessments_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.update_medical_documents_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION public.update_ocr_jobs_updated_at()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;